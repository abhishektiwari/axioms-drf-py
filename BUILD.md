
# Install dependencies

```
pip install twine
pip install wheel
python3 -m pip install --user --upgrade setuptools wheel twine
```

# Set token
Create `HOME/.pypirc` and add PyPI API token.

```
[pypi]
username = __token__
password = <the token value, including the `pypi-` prefix>
```

# Build the wheel

```
python3 setup.py sdist bdist_wheel
```


# Upload your distribution

```
twine upload dist/*
```

# Working in development mode
Add following in `requirements.txt` file

```
-e /path/to/axioms-drf-py
```

or

```
pip install -e /path/to/axioms-drf-py
```

or

```
python3 setup.py develop
```