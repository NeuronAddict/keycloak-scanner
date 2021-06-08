import io
import re

from pkg_resources import parse_requirements
from setuptools import setup, find_packages

install_requires = parse_requirements('requirements.in')

with open('requirements.in') as file:
    dependencies = file.readlines()

with open("README.md", "r") as fh:
    long_description = fh.read()

__version__ = re.search(r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]',  # It excludes inline comment too
          io.open('keycloak_scanner/_version.py', encoding='utf_8_sig').read()
          ).group(1)

setup(name='keycloak-scanner',
      version=__version__,
      description='Keycloak vulnerabilities scanner',
      url='http://github.com/neuronaddict/keycloak-scanner',
      author='neuronaddict',
      author_email='',
      long_description=long_description,
      long_description_content_type="text/markdown",
      entry_points={
          'console_scripts': [
              'keycloak-scanner = keycloak_scanner.main:main'
          ]
      },
      license='Apache 2.0',
      packages=find_packages(),
      zip_safe=False, install_requires=dependencies,
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: Apache Software License",
          "Operating System :: OS Independent",
      ],
      python_requires='>=3.6')
