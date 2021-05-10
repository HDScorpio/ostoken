import click

from ostoken.commands.proxy import proxy_command


@click.group()
@click.help_option('-h', '--help')
@click.option('-d', '--debug', is_flag=True, default=False)
@click.pass_context
def cli(ctx, debug):
    """ Command line utility to work with OpenStack tokens """
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug


cli.command('proxy')(proxy_command)


if __name__ == '__main__':
    cli()
