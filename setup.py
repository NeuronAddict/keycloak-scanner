from setuptools import setup

setup(name='keycloak-scanner',
      version='0.1',
      description='Keycloak vulnerabilities scanner',
      url='http://github.com/neuronaddict/keycloak-scanner',
      author='neuronaddict',
      author_email='',
      entry_points={
          'console_scripts': [
              'keycloak-scanner = keycloak_scanner.main:main'
          ]
      },
      license='GNUv3',
      packages=['keycloak_scanner'],
      zip_safe=False, install_requires=['requests', 'termcolor', 'pyjwt'])
