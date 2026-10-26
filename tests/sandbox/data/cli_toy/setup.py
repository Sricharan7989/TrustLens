from setuptools import setup
setup(name='cli-toy', version='0.1', packages=['cli_toy'], description='synthetic TrustLens toy',
      entry_points={'console_scripts': ['cli-toy=cli_toy.cli:main']})
