from setuptools import find_packages, setup

setup(
    name='observatory',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
      'flask',
      'pycrypto',
      'pytest',
      'requests',
      'xmltodict',
    ],
)
