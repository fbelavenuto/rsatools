# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages


# Utility function to read the contents of a file.
def _read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup_options = dict(
    name='rsatools',
    version='0.1',
    author='Fabio Belavenuto (@fbelavenuto)',
    author_email='belavenuto@gmail.com',
    url='https://github.com/fbelavenuto/rsatools',
    license='MIT License',
    description='RSA cipher tools',
    long_description=_read('README.md'),
    packages=find_packages(),
    entry_points={
        'console_scripts': 'rsatools = rsatools.cli:main'
    },
    install_requires=_read('requirements.txt').splitlines(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Utilities",
    ],
)

setup(**setup_options)