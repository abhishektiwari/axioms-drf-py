API Reference
=============

This page contains the full API reference for axioms-drf-py, automatically generated from the source code docstrings.

Core Configuration
------------------

The SDK requires the following Django settings to be configured:

=====================  ========  =========================================================================
Parameter              Required  Description
=====================  ========  =========================================================================
``AXIOMS_AUDIENCE``    Yes       Expected audience claim in the JWT token.
``AXIOMS_DOMAIN``      No        Axioms domain name. Used as the base to construct ``AXIOMS_ISS_URL``
                                 if not explicitly provided. This is the simplest configuration option
                                 for standard OAuth2/OIDC providers.
``AXIOMS_ISS_URL``     No        Full issuer URL for validating the ``iss`` claim in JWT tokens
                                 (e.g., ``https://auth.example.com/oauth2``). If not provided,
                                 constructed as ``https://{AXIOMS_DOMAIN}``. Used to construct
                                 ``AXIOMS_JWKS_URL`` if that is not explicitly set. Recommended for
                                 security to prevent token substitution attacks.
``AXIOMS_JWKS_URL``    No        Full URL to JWKS endpoint (e.g.,
                                 ``https://auth.example.com/.well-known/jwks.json``).
                                 If not provided, constructed as
                                 ``{AXIOMS_ISS_URL}/.well-known/jwks.json``
=====================  ========  =========================================================================

.. important::

    Either ``AXIOMS_JWKS_URL``, ``AXIOMS_ISS_URL``, or ``AXIOMS_DOMAIN`` must be configured for token validation.

    **Configuration Hierarchy:**

    The SDK uses the following construction order:

    1. ``AXIOMS_DOMAIN`` → constructs → ``AXIOMS_ISS_URL`` (if not explicitly set)
    2. ``AXIOMS_ISS_URL`` → constructs → ``AXIOMS_JWKS_URL`` (if not explicitly set)

    **Example:** Setting only ``AXIOMS_DOMAIN=auth.example.com/oauth`` results in:

    - ``AXIOMS_ISS_URL``: ``https://auth.example.com/oauth``
    - ``AXIOMS_JWKS_URL``: ``https://auth.example.com/oauth/.well-known/jwks.json``

Security & Algorithm Validation
--------------------------------

The SDK implements multiple security best practices to prevent common JWT attacks:

**Algorithm Validation**

Only secure asymmetric algorithms are accepted for JWT signature verification. The SDK validates that:

1. The ``alg`` header in the JWT specifies an allowed algorithm
2. Each key is used with exactly one algorithm
3. The algorithm validation occurs before cryptographic operations

**Supported Algorithms:**

- **RSA**: RS256, RS384, RS512
- **ECDSA**: ES256, ES384, ES512
- **RSA-PSS**: PS256, PS384, PS512

**Rejected Algorithms:**

- ``none`` - No signature (critical security vulnerability)
- ``HS256``, ``HS384``, ``HS512`` - Symmetric algorithms (prevents key confusion attacks)
- Any algorithm not in the allowed list above

This prevents algorithm confusion attacks where an attacker might try to:

- Use the ``none`` algorithm to bypass signature verification
- Substitute an asymmetric algorithm with a symmetric one
- Use weak or deprecated algorithms

**Additional Security Features:**

- Issuer validation (``iss`` claim) to prevent token substitution
- Automatic public key retrieval and validation from JWKS endpoints
- Token expiration validation
- Audience claim validation
- Key ID (``kid``) validation

Claim Name Mapping
------------------

Configure custom claim names to support different authorization servers (`AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_, `Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_, `Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_). These mapping options provide additional customization for claim names used to extract scopes, roles, and permissions from the JWT token. These mappings can also support `RFC 9068 <https://datatracker.ietf.org/doc/html/rfc9068>`_ JWT Profile for OAuth 2.0 Access Tokens.

+------------------------------+----------+----------------------------------------------------------------------------+
| Parameter                    | Required | Description                                                                |
+==============================+==========+============================================================================+
| ``AXIOMS_SCOPE_CLAIMS``      | No       | List of scope claim names to check in priority order.                      |
|                              |          |                                                                            |
|                              |          | Default: ``['scope']``                                                     |
|                              |          |                                                                            |
|                              |          | Example: ``['scope', 'scp']``                                              |
+------------------------------+----------+----------------------------------------------------------------------------+
| ``AXIOMS_ROLES_CLAIMS``      | No       | List of role claim names to check in priority order.                       |
|                              |          |                                                                            |
|                              |          | Default: ``['roles']``                                                     |
|                              |          |                                                                            |
|                              |          | Example: ``['roles', 'cognito:roles']``                                    |
+------------------------------+----------+----------------------------------------------------------------------------+
| ``AXIOMS_PERMISSIONS_CLAIMS``| No       | List of permission claim names to check in priority order.                 |
|                              |          |                                                                            |
|                              |          | Default: ``['permissions']``                                               |
|                              |          |                                                                            |
|                              |          | Example: ``['permissions', 'cognito:groups', 'groups', 'entitlements']``   |
+------------------------------+----------+----------------------------------------------------------------------------+

.. important::

   **Namespaced Claims:** You can specify namespaced claim names directly in the claim configuration lists.

   The SDK will check claims in the order you specify them, using the first non-None value found.

   Example: ``AXIOMS_ROLES_CLAIMS = ['roles', 'https://myapp.com/claims/roles', 'cognito:groups']``

Setting Django Settings
^^^^^^^^^^^^^^^^^^^^^^^^

You can configure these settings in your Django ``settings.py`` file:

.. code-block:: python

   # Required
   AXIOMS_AUDIENCE = 'your-api-audience-or-resource-identifier'

   # Option 1: Use AXIOMS_DOMAIN (simplest)
   AXIOMS_DOMAIN = 'your-domain.axioms.io'

   # Option 2: Use AXIOMS_ISS_URL (more control)
   # AXIOMS_ISS_URL = 'https://my-auth.domain.com/oauth2'

   # Option 3: Use AXIOMS_JWKS_URL (full control)
   # AXIOMS_JWKS_URL = 'https://my-auth.domain.com/oauth2/.well-known/jwks.json'

   # Optional: Custom claim names
   # AXIOMS_SCOPE_CLAIMS = ['scope', 'scp']
   # AXIOMS_ROLES_CLAIMS = ['roles', 'cognito:groups']
   # AXIOMS_PERMISSIONS_CLAIMS = ['permissions', 'custom:permissions']



Middleware
----------

The middleware module provides Django middleware for JWT token extraction and validation.

.. automodule:: axioms_drf.middleware
   :members:
   :undoc-members:
   :show-inheritance:

Authentication Classes
----------------------

The authentication module provides Django REST Framework authentication classes for JWT token validation.

.. automodule:: axioms_drf.authentication
   :members:
   :undoc-members:
   :show-inheritance:

Permission Classes
------------------

The permissions module provides Django REST Framework permission classes for claim-based authorization.

.. automodule:: axioms_drf.permissions
   :members:
   :undoc-members:
   :show-inheritance:

Helper Functions
----------------

The helper module provides utility functions for token validation and claim extraction.

.. automodule:: axioms_drf.helper
   :members:
   :undoc-members:
   :show-inheritance:
