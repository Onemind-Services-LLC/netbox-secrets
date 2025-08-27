import os

from setuptools import find_packages, setup

description = "Enhance your secret management with encrypted storage and flexible, user-friendly features."

readme = os.path.join(os.path.dirname(__file__), 'README.md')

with open(readme) as fh:
    long_description = fh.read()


# Read install requirements from requirements.txt
def read_requirements(path: str) -> list[str]:
    reqs = []
    req_file = os.path.join(os.path.dirname(__file__), path)
    if not os.path.exists(req_file):
        return reqs
    with open(req_file) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('-') or line.startswith('--'):
                # Skip options like -r, --find-links, etc.
                continue
            if ' #' in line:
                # Drop inline comments added by pip-compile
                line = line.split(' #', 1)[0].strip()
            reqs.append(line)
    return reqs


setup(
    name='netbox-secrets',
    version='2.3.2',
    description=description,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Onemind-Services-LLC/netbox-secrets/',
    author='Abhimanyu Saharan',
    author_email='asaharan@onemindservices.com',
    maintainer="Prince Kumar",
    maintainer_email="pkumar@onemindservices.com",
    license='Apache 2.0',
    install_requires=read_requirements('requirements.txt'),
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    zip_safe=False,
)
