# coding=utf-8
import setproctitle
from datetime import datetime
from collections import namedtuple
from lockfile.pidlockfile import PIDLockFile
import logging
import json
from shutil import copyfileobj
import os
import signal
import sys
from threading import Lock, RLock
from uuid import uuid4

import daemon
import click
import requests
from requests.auth import AuthBase
import psutil

if sys.version_info[0] == 2:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
    from urlparse import urlparse
else:
    from http.server import BaseHTTPRequestHandler
    from http.server import ThreadingHTTPServer as HTTPServer
    from urllib.parse import urlparse

logger = logging.getLogger()

access_logger = logging.getLogger(__name__)
access_logger.setLevel(logging.INFO)
access_logger.addHandler(logging.NullHandler())
access_logger.propagate = False

CACHE_DIR = os.path.expanduser('~/.cache/ostoken')


class TokenCache(object):
    """ Класс, реализующий кэширование токенов """

    _CValue = namedtuple('CValue', [
        'token_id',  # значение токена
        'token_info',  # информация о токене
        'headers',  # заголовки ответа Keystone
        'keys'  # ключи кэширования текущего токена
    ])

    def __init__(self):
        self._cache = {}
        # Блокировка доступа к кэшу между разными потоками
        self._lock = RLock()

    def set(self, token_info, headers):
        """ Кэширование токена и заголовков, полученных при получении токена

        Токен кэшируется по следющим возможным ключам:
          - <token_id>
          - 'unscoped'
          - <project_id>
          - <project_name>@<project_domain_name>
          - <project_name>@<project_domain_id>

        :param token_info: информация о токене
        :param headers: заголовки ответа от Keystone
        """
        keys = self._get_project_keys(token_info['token'])
        token_id = headers.get('X-Subject-Token')
        keys.append(token_id)
        cvalue = self._CValue(token_id, token_info, headers, keys)
        logger.debug('Cache set: token_id=...%s, expires_at=%s',
                     token_id[-10:],
                     token_info['token']['expires_at'])
        with self._lock:
            for key in keys:
                self._cache[key] = cvalue

    def get(self, auth_info):
        """ Получение токена из кэша

        Невалидные токены автоматически удаляются из кэша.

        :param auth_info: аутентификационная информация
        :return: token_info, headers
        """
        keys = self._get_project_keys(auth_info['auth']['scope'])
        with self._lock:
            for key in keys:
                cvalue = self._cache.get(key, None)
                if cvalue:
                    break
            else:
                logger.debug('Cache miss')
                return None, None

            if not self._is_valid(cvalue):
                logger.debug('Cache invalid: token_id=...%s, '
                             'expires_at=%s',
                             cvalue.token_id[-10:],
                             cvalue.token_info['token']['expires_at'])
                self._flush(cvalue)
                return None, None

            logger.debug('Cache hit: token_id=...%s, expires_at=%s',
                         cvalue.token_id[-10:],
                         cvalue.token_info['token']['expires_at'])
            return cvalue.token_info, cvalue.headers

    def _flush(self, cvalue):
        """ Удаление токена из кэша """
        with self._lock:
            for key in cvalue.keys:
                self._cache.pop(key)

    @staticmethod
    def _get_project_keys(project_info):
        """ Создание ключей для кэширования токена по информации о проекте

        Возможные ключи:
          - 'unscoped'
          - <project_id>
          - <project_name>@<project_domain_name>
          - <project_name>@<project_domain_id>
        """
        if project_info == 'unscoped':
            # запрос на получение unscope токена
            return [project_info]

        if 'project' not in project_info:
            # получен unscope токен
            return ['unscoped']

        project = project_info['project']
        keys = []

        if 'id' in project:
            keys.append(project['id'])
        if 'name' in project:
            if 'domain' in project:
                for domain in project['domain'].values():
                    keys.append('%s@%s' % (project['name'], domain))
        return keys

    @staticmethod
    def _is_valid(cvalue):
        """ Валидация токена

        Если время жизни токена меньше 1 минуты, то не валиден.
        """
        expires_at_str = cvalue.token_info['token']['expires_at']
        expires_at = datetime.strptime(expires_at_str,
                                       '%Y-%m-%dT%H:%M:%S.%fZ')
        now = datetime.utcnow()
        delta = (expires_at - now).total_seconds()
        if delta < 60:
            return False
        return True


CACHE = TokenCache()


class KerberosAuth(AuthBase):
    user = None

    def __init__(self, scope):
        self.scope = scope

    def __call__(self, r):
        auth = json.dumps(
            {
                'auth': {
                    'scope': self.scope,
                    'identity': {
                        'methods': ['kerberos'],
                        'kerberos': {}
                    }
                }
            }
        )
        r.body = auth
        return r

    @classmethod
    def get_user(cls):
        return cls.user


class PasswordAuth(AuthBase):
    user = None
    domain = None
    password = None

    def __init__(self, scope):
        self.scope = scope

    def __call__(self, r):
        auth = json.dumps(
            {
                'auth': {
                    'scope': self.scope,
                    'identity': {
                        'methods': ['password'],
                        'password': {
                            'user': {
                                'password': self.password,
                                'name': self.user,
                                'domain': {'name': self.domain}
                            }
                        }
                    }
                }
            }
        )
        r.body = auth
        return r

    @classmethod
    def get_user(cls):
        return '%s@%s' % (cls.user, cls.domain)


def touch(filepath):
    """ Создание файла журнала с правами доступа 0600

    Если файл существует, то он удаляется, чтобы старый процесс не записал
    данные в существующий журнал, при старте нового процесса.
    """
    if os.path.exists(filepath):
        os.remove(filepath)
    fd = os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_EXCL, mode=0o600)
    os.close(fd)


def setup_logging(debug=False, console=False):
    """ Настройка логирования """
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, mode=0o700)

    access_log_file = os.path.join(CACHE_DIR, 'proxy_access.log')
    touch(access_log_file)
    access_h = logging.FileHandler(access_log_file, mode='w')
    access_h.setFormatter(logging.Formatter('%(message)s'))
    access_h.setLevel(logging.INFO)
    access_logger.addHandler(access_h)

    error_log_file = os.path.join(CACHE_DIR, 'proxy_error.log')
    touch(error_log_file)
    error_h = logging.FileHandler(error_log_file, mode='w')
    # Формат логирования в стиле Apache
    error_h.setFormatter(logging.Formatter(
        '[%(asctime)s] [%(name)s:%(levelname)s] [tid:%(thread)d] %(message)s'))
    logger.addHandler(error_h)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if console:
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.DEBUG)
        console.setFormatter(
            logging.Formatter('[%(name)s %(thread)d %(levelname)s] '
                              '%(message)s'))
        access_logger.addHandler(console)
        logger.addHandler(console)

    return access_h.stream, error_h.stream


class StreamToLogger(object):
    """ Класс для перенаправления STDOUT/STDERR в систему логирования """

    def __init__(self, name, level):
        self.name = name
        self.level = level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            logger.log(self.level, '%s: %s', self.name, line.rstrip())

    def flush(self):
        pass


class KeystoneProxyServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = 'ostoken.proxy/0.1.0.a1'

    auth_url = None
    auth_plugin = None

    access_key = uuid4().hex
    uid = os.getuid()

    _request_lock = Lock()

    def __init__(self, *args, **kwargs):
        self._log_size = '-'
        self._log_process = '-'
        self._log_user_agent = '-'
        self._log_referer = '-'

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def __getattr__(self, item):
        """ Подмена реализация методов запроса на функцию перенаправления """
        if item.startswith('do_'):
            return self.do_redirect
        raise AttributeError

    def do_POST(self):
        """ Обработка запроса на получение токена """
        if '/v3/auth/tokens' not in self.path:
            return self.do_redirect()

        if not self.authorize():
            return

        # FIXME: обрабатывать параметр запроса ?nocatalog:
        #  - кэшировать всегда с каталогом
        #  - возвращать информацию в зависимости от параметра
        logger.debug('Checking token_info cache')
        content_type = self.headers.get('Content-Type', None)
        if not content_type or content_type != 'application/json':
            msg = "Expected content type JSON, but got '%s'" % content_type
            self.send_error(400, msg)
            return

        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            msg = 'Content length is not present or equal 0'
            self.send_error(400, msg)
            return

        data = self.rfile.read(length)
        try:
            auth_info = json.loads(data)
        except (ValueError, TypeError) as e:
            msg = 'Failed to parse incoming JSON'
            self.send_error(400, msg)
            self.log_error(str(e))
            return

        # Получение токена из кэша
        try:
            token_info, headers = CACHE.get(auth_info)
        except KeyError as e:
            msg = ("Failed to parse authentication info: key %s expected" %
                   str(e))
            self.send_error(400, msg)
            return

        if not token_info:
            # NOTE: блокировка используется для того, чтобы избежать получения
            # нескольких токенов при их одновременном запросе несколькими
            # процессами, когда кэш оказался пустой
            with self._request_lock:
                # Повторно проверяем кэш на случай,
                # если он был обновлен другим потоком
                token_info, headers = CACHE.get(auth_info)
                if not token_info:
                    # Перенаправляем запрос в Keystone для получения
                    # нового токена
                    logger.debug('Requesting new token_info')
                    resp = self.do_request(
                        auth=self.auth_plugin(auth_info['auth']['scope']))
                    if resp is None:
                        return

                    if not resp.ok:
                        self.do_response(resp.status_code, resp.headers,
                                         resp.raw)
                        return

                    token_info = resp.json()
                    headers = resp.headers.copy()

                    # Кэшируем полученный токен
                    CACHE.set(token_info, headers)

        # Отвечаем клиенту
        body = json.dumps(token_info).encode('utf-8')
        self._log_size = str(len(body))
        headers['Content-Length'] = self._log_size
        self.do_response(201, headers, body)

    # def do_DELETE(self):
    #     """ Отзыв токена """
    #     if '/v3/auth/tokens' not in self.path:
    #         return self.do_redirect()
    #
    #     if not self.authorize():
    #         return
    #
    # def do_HEAD(self):
    #     """ Валидация токена """
    #     if '/v3/auth/tokens' not in self.path:
    #         return self.do_redirect()
    #
    #     if not self.authorize():
    #         return
    #
    # def do_GET(self):
    #     """ Получение информации о токене """
    #     if '/v3/auth/tokens' not in self.path:
    #         return self.do_redirect()
    #
    #     if not self.authorize():
    #         return

    def do_redirect(self):
        """ Перенаправлние запроса в Keystone """
        if not self.authorize():
            return

        logger.debug('Redirecting request')
        resp = self.do_request(data=self.rfile)
        if resp is None:
            return

        self.do_response(resp.status_code, resp.headers, resp.raw)

    def do_request(self, data=None, auth=None):
        if data and hasattr(data, 'read') and callable(data.read):
            # NOTE: self.rfile - сокет, где соединение не закрывается из-за
            #   протокола HTTP/1.1. Поэтому нельзя просто использовать
            #   self.rfile.read(), т.к. произойдет зависание.
            length = int(self.headers.get('Content-Length', 0))
            data = data.read(length)

        headers = {}
        for k, v in self.headers.items():
            # В py2 заголовки в нижнем регистре ('host'), в py3 - в верхнем
            if k.lower() in ('host', 'content-length'):
                continue
            headers[k] = v

        # NOTE: используем подготовленный запрос, чтобы установить только те
        #   заголовки, которые пришли от клиента, иначе requests добавляет
        #   собственные (Connection, Accept-Encoding)
        pre = requests.Request(
            method=self.command.lower(),
            url=self.auth_url + self.path.lstrip('/'),
            headers=headers,
            data=data,
            auth=auth
        ).prepare()

        logger.debug('Request: %s %s', pre.method, pre.url)
        logger.debug('Request HEADERS: %s', pre.headers)

        try:
            resp = requests.Session().send(pre, stream=True, timeout=10)
        except requests.ConnectionError as e:
            self.send_error(502, 'Connect to Keystone by ostoken.proxy '
                                 'raised error: %s' % e)
            return
        except requests.Timeout:
            self.send_error(504, 'Request to Keystone by ostoken.proxy '
                                 'exceed timeout')
            return

        self._log_size = resp.headers.get('Content-Length', '-')
        return resp

    def do_response(self, code, headers, data):
        logger.debug('Response: %s', code)
        logger.debug('Response HEADERS: %s', headers)

        self.send_response(code)
        for k, v in headers.items():
            if k.lower() in ('date', 'server'):
                continue
            self.send_header(k, v)
        self.end_headers()

        if hasattr(data, 'read') and callable(data.read):
            copyfileobj(data, self.wfile)
        else:
            self.wfile.write(data)

    def authorize(self):
        """ Авторизация запроса по ключу доступа и uid процесса """
        self._log_referer = self.headers.get('Referer', '-')
        self._log_user_agent = self.headers.get('User-Agent', '-')

        # Проверяем процесс - uid должен совпадать
        process = None
        client_port = self.client_address[1]
        for proc in psutil.process_iter(['uids']):
            try:
                # Поиск только среди процессов с тем же uid
                if proc.info['uids'].real != self.uid:
                    continue

                for conns in proc.connections(kind='tcp4'):
                    if conns.laddr.port == client_port:
                        process = proc
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if process:
                break

        if not process:
            self.send_error(403, 'Process is not allowed access')
            return False

        with process.oneshot():
            self._log_process = process.name()
            cmdline = process.cmdline()

        logger.debug('Request cmdline: %s', cmdline)

        # Проверяем ключ доступа
        parts = self.path.split('/')
        key = parts.pop(1)
        if key != self.access_key:
            self.send_error(403, 'Access key is not present or invalid')
            return False

        self.path = '/'.join(parts)

        return True

    def log_request(self, code='-', size='-'):
        """ Логирование запросов в формате 'Combined Log' """
        access_logger.info(
            '{host:s} {process:s} {user:s} [{date:s}] "{request_line:s}" '
            '{code:s} {size:s} "{referer:s}" "{user_agent:s}"'.format(
                host=self.client_address[0],
                process=self._log_process,
                user=self.auth_plugin.get_user(),
                date=self.log_date_time_string(),
                request_line=self.requestline.replace('/' + self.access_key,
                                                      ''),
                code=str(code),
                size=self._log_size if size == '-' else size,
                referer=self._log_referer,
                user_agent=self._log_user_agent))

    def log_error(self, msg, *args):
        logger.error(msg, *args)

    def send_error(self, code, message=None):
        """ Отправка сообщения об ошибке в стиле Keystone

        Тело сообщения представлено в виде JSON
        """
        title = self.responses[code][0]
        error = {
            'error': {
                'code': code,
                'title': title,
                'message': message
            }
        }
        self.log_error('code=%s, title=%s, message=%s', code, title, message)
        body = json.dumps(error).encode('utf-8')
        self._log_size = str(len(body))

        self.send_response(code, title)
        self.send_header('Content-Length', self._log_size)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Connection', 'close')
        self.end_headers()

        if self.command != 'HEAD':
            self.wfile.write(body)


@click.help_option('-h', '--help')
@click.option('--auth-type',
              type=click.Choice(['password', 'v3password', 'v3kerberos']),
              envvar='OS_AUTH_TYPE',
              default='password',
              help='authentication scheme type')
@click.option('--auth-url',
              type=str,
              envvar='OS_AUTH_URL',
              default=None,
              help='Keystone address URL')
@click.option('--port',
              type=int,
              default=0,
              help='port number to bind, default is any free')
@click.option('-u', '--user',
              type=str,
              envvar='OS_USERNAME',
              help='user name')
@click.option('-d', '--domain',
              type=str,
              envvar='OS_USER_DOMAIN_NAME',
              help='user domain name')
@click.option('-p', '--password',
              type=str,
              envvar='OS_PASSWORD',
              help="user password")
@click.option('-f', '--foreground',
              type=bool,
              is_flag=True,
              default=False,
              help='run in foreground (requests will be log to stdout)')
@click.option('--no-check',
              type=bool,
              is_flag=True,
              default=False,
              help='do not check user/password in Keystone at startup')
@click.pass_context
def proxy_command(ctx, auth_type, auth_url, port,
                  user, domain, password,
                  foreground, no_check):
    """
    Start a caching proxy server to the Keystone service
    """
    address = ('127.0.0.1', port)

    # Скрытие аргументов запуска прокси из списка процессов
    setproctitle.setproctitle('ostoken proxy')

    if not user:
        click.echo('Username required', err=True)
        sys.exit(1)

    if 'password' in auth_type:
        if not domain:
            click.echo('User domain name required', err=True)
            sys.exit(1)

        if not password:
            click.echo('Password required', err=True)
            sys.exit(1)

        PasswordAuth.user = user
        PasswordAuth.domain = domain
        PasswordAuth.password = password

        KeystoneProxyServer.auth_plugin = PasswordAuth
    else:
        KerberosAuth.user = user
        KeystoneProxyServer.auth_plugin = KerberosAuth

    if not auth_url:
        click.echo('Keystone URL required', err=True)
        sys.exit(1)

    # Удялем из URL параметры запроса и фрагменты
    p = urlparse(auth_url)
    path = p.path.strip('/')
    auth_url = '{scheme:s}://{netloc:s}/{path:s}'.format(
        scheme=p.scheme,
        netloc=p.netloc,
        path=path + '/' if path else '')
    # Удаляем избыточное указание версии протокола
    auth_url = auth_url.replace('/v3', '')
    KeystoneProxyServer.auth_url = auth_url

    if not no_check:
        try:
            resp = requests.post(
                auth_url + 'v3/auth/tokens',
                auth=KeystoneProxyServer.auth_plugin('unscoped')
            )
        except requests.ConnectionError as e:
            click.echo(e, err=True)
            sys.exit(1)

        if resp.status_code != 201:
            click.echo('Failed to get unscope token to check credentials: '
                       '%s %s\n%s' % (resp.status_code, resp.reason,
                                      resp.content),
                       err=True)
            sys.exit(1)

        token_info = resp.json()
        headers = resp.headers.copy()
        CACHE.set(token_info, headers)

    proxy_access_f, proxy_error_f = \
        setup_logging(debug=ctx.obj.get('debug', False), console=foreground)

    logger.info('auth_type: %s', auth_type)
    logger.info('auth_url: %s', auth_url)
    logger.info('user: %s@%s', user, domain)
    logger.info('password: %s', '*' * len(password))
    logger.info('uid: %d', KeystoneProxyServer.uid)

    server = HTTPServer(address, KeystoneProxyServer)
    host, port = server.socket.getsockname()[:2]
    click.echo('export OS_AUTH_URL=http://%s:%d/%s/v3' % (
        host, port, KeystoneProxyServer.access_key))

    # Проверяем наличие уже запущенного сервера
    pidfile = PIDLockFile(os.path.join(CACHE_DIR, 'proxy.pid'),
                          timeout=5)
    if pidfile.is_locked():
        # Останавливаем предыдущий сервер
        prev_pid = pidfile.read_pid()
        os.kill(prev_pid, signal.SIGTERM)

    try:
        if foreground:
            with pidfile:
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    logger.info('Stopping server: '
                                'keyboard interrupt received.')
        else:
            daemon_ctx = daemon.DaemonContext(
                working_directory=CACHE_DIR,
                umask=0o077,
                pidfile=pidfile,
                files_preserve=[proxy_access_f, proxy_error_f, server.socket],
                signal_map={
                    signal.SIGTERM: 'terminate',
                    signal.SIGINT: 'terminate'
                }
            )
            try:
                with daemon_ctx:
                    # После старта демона перенаправляем stdout/stderr в
                    # систему логирования
                    sys.stdout = StreamToLogger('STDOUT', logging.INFO)
                    sys.stderr = StreamToLogger('STDERR', logging.ERROR)
                    logger.info('Server started')
                    server.serve_forever()
            except SystemExit as e:
                logger.info('Stopping server: %s', e)
    finally:
        server.server_close()
    logger.info('Server stopped')
