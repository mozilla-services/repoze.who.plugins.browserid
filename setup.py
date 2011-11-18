
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['repoze.who', 'unittest2', 'webtest']

setup(name='repoze.who.plugins.browserid',
      version='0.1',
      description='repoze.who.plugins.browserid',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        ],
      author='',
      author_email='',
      url='',
      keywords='authentication repoze browserid',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      test_suite="repoze.who.plugins.browserid")
