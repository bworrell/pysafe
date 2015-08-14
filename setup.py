#!/usr/bin/env python
# Copyright (c) 2015 - Bryan Worrell
# For license information, see the LICENSE file
import os
import setuptools

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(BASE_DIR, "pysafe", 'version.py')
README_FILE  = os.path.join(BASE_DIR, "README.rst")


def normalize(version):
    return version.split()[-1].strip("\"'")


def get_version():
    with open(VERSION_FILE) as f:
        verlines  = (line for line in f if line.startswith("__version__"))
        version   = next(verlines)
        return normalize(version)


with open(README_FILE) as f:
    readme = f.read()


install_requires = [
    'pyperclip>=1.3',
    'python-mcrypt>=1.1'
]

extras_require = {}

setuptools.setup(
    name='pysafe',
    description='A Python API for PasswordSafe.',
    author='Bryan Worrell',
    author_email='',
    url='https://github.com/bworrell',
    version=get_version(),
    packages=setuptools.find_packages(),
    scripts=['pysafe/scripts/pysafe-get.py'],
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    long_description=readme,
    keywords="PasswordSafe pwsafe pysafe"
)
