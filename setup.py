import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="axioms-drf-py",
    version="0.0.4",
    author="Axioms",
    author_email="info@axioms.io",
    description="Django REST Framework (DRF) SDK for Axioms",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/axioms-io/axioms-drf-py",
    license='MIT',
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={'': 'src'},
    packages=setuptools.find_packages(where='src'),
    python_requires='>=3.7',
    keywords='axioms authentication authorization iam authz authn jwt openid oauth2',
    project_urls={
        'Documentation': 'https://github.com/axioms-io/axioms-drf-py',
        'Source': 'https://github.com/axioms-io/axioms-drf-py',
        'Tracker': 'https://github.com/axioms-io/axioms-drf-py/issues',
    },
    install_requires=[
        'pyjwt',
        'jwcrypto',
        'python-box',
        'django >= 2.0'
        'djangorestframework',
        'requests<3',
        'django-environ'
    ]
)