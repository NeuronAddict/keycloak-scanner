from setuptools import setup

setup(name='openid-scanner',
      version='0.1',
      description='OpenID scanner',
      url='http://github.com/neuronaddict/openid-scanner',
      author='neuronaddict',
      author_email='',
      license='GNUv3',
      packages=['openid_scanner'],
      zip_safe=False, install_requires=['requests', 'termcolor'])
