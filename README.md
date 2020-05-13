# axioms-drf-py ![PyPI](https://img.shields.io/pypi/v/axioms-drf-py)
[Axioms](https://axioms.io) Python client for Django Rest Framework (DRF). Secure your DRF APIs using Axioms Authentication and Authorization.

## Prerequisite

* Python 3.7+
* An [Axioms](https://axioms.io) client which can obtain access token after user's authentication and authorization and include obtained access token as bearer in `Authorization` header of all API request sent to Python/Django/DRF application server.

## Install SDK
Install `axioms-drf-py` in you DRF API project,

```
pip install axioms-drf-py
```

## Documentation
See [documentation](https://developer.axioms.io/docs/sdks-samples/use-with-apis/python/django-apis) for `axioms-drf-py`.

## DRF Sample
To see a complete working example download [DRF sample](https://github.com/axioms-io/sample-python-drf) from our Github repository or simply deploy to Heroku by clicking following button. You will need to provide Axioms domain and Axioms audience to complete deployment.

<a href="https://heroku.com/deploy?template=https://github.com/axioms-io/sample-python-flask">
  <img src="https://www.herokucdn.com/deploy/button.svg" alt="Deploy" width="200px" />
</a>
