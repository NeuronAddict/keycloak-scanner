from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='keycloak-scanner',
      version='0.2.0',
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
      packages=['keycloak_scanner'],
      zip_safe=False, install_requires=['requests', 'termcolor', 'pyjwt', 'urllib3'],
      classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
      ],
      python_requires='>=3.6')
