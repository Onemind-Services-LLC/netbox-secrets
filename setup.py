import os

from setuptools import find_packages, setup

description = "Enhance your secret management with encrypted storage and flexible, user-friendly features."

readme = os.path.join(os.path.dirname(__file__), 'README.md')

with open(readme) as fh:
    long_description = fh.read()

setup(
    name='netbox-secrets',
    version='2.0.3',
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Onemind-Services-LLC/netbox-secrets/',
    author='Abhimanyu Saharan',
    author_email='asaharan@onemindservices.com',
    maintainer="Prince Kumar",
    maintainer_email="pkumar@onemindservices.com",
    license='Apache 2.0',
    install_requires=[
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
