from setuptools import find_packages, setup

setup(
    name='netbox-secretstore',
    version='1.0.6',
    description='A Secret store for NetBox',
    url='https://github.com/dansheps/netbox-secretstore',
    author='Daniel Sheppard',
    author_email='dans@dansheps.com',
    license='Apache 2.0',
    install_requires=[
        'netbox-plugin-extensions'
    ],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    zip_safe=False,
)
