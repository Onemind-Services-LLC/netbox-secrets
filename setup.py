from setuptools import find_packages, setup

setup(
    name='netbox-secretstore',
    version='0.1',
    description='A Secret store for NetBox',
    url='https://github.com/netbox-community/netbox-secretstore',
    author='NetBox Maintainers',
    license='Apache 2.0',
    install_requires=[],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)