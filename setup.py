from setuptools import find_packages, setup

description = """
Enhance your secret management with encrypted storage and flexible, user-friendly features, seamlessly integrated into
the NetBox environment.
"""

long_description="""
# NetBox Secrets

NetBox Secrets is a comprehensive overhaul of the original NetBox Secretstore plugin. It's designed to address the 
limitations and maintenance challenges of the predecessor. This plugin introduces significant enhancements in terms of 
flexibility and usability, ensuring seamless integration with the latest NetBox versions.

## Key Features:

- Employs RSA public key cryptography for secure storage of secrets in the database.
- Allows secrets to be assigned to any object in NetBox, enhancing the plugin’s applicability and utility.
- Enables assigning secrets to contacts, ideal for scenarios like linking SSH keys with specific individuals.
- The redesigned interface is more intuitive and user-friendly, streamlining navigation and secret management.
- Continuous testing with the latest NetBox releases ensures consistent compatibility and reliability.

NetBox Secrets is committed to bridging the gap between robust security needs and an optimal user experience in NetBox
environments.
"""

setup(
    name='netbox-secrets',
    version='1.9.1',
    description=description,
    long_description=long_description,
    url='https://github.com/Onemind-Services-LLC/netbox-secrets/',
    author='Abhimanyu Saharan',
    author_email='asaharan@onemindservices.com',
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
