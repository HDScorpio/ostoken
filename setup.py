from setuptools import setup

setup(
    name='ostoken',
    version='0.1.0.a1',
    description='console utility to work with OpenStack tokens',
    license='MIT',
    author='Andrey Ulagashev',
    author_email='ulagashev.andrey@gmail.com',
    url='https://github.com/HDScorpio/ostoken',
    packages=[
        'ostoken',
        'ostoken.commands',
    ],
    install_requires=[
        'click',
        'requests',
        'setproctitle',
        'psutil',
        'python-daemon'
    ],
    entry_points={
        'console_scripts': [
            'ostoken = ostoken.main:cli'
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP'
    ],
)

