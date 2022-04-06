from setuptools import find_packages, setup

setup(
    name='netbox-secretstore',
    version='1.0.16',
    description='Netbox Secret Store',
    long_description='A Secret store for NetBox',
    url='https://github.com/dansheps/netbox-secretstore/',
    download_url='https://www.pypi.org/project/netbox-secretstore/',
    author='Daniel Sheppard',
    author_email='dans@dansheps.com',
    license='Apache 2.0',
    install_requires=[
        'importlib',
        'pycryptodome',
    ],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    zip_safe=False,
)
