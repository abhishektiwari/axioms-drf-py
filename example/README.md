# Axioms DRF Example Application

This is a complete example Django REST Framework application demonstrating the `axioms-drf-py` library for JWT-based authentication and authorization.

This example demonstrates:

- Public endpoints - No authentication required
- Authenticated endpoints - Requires valid JWT token
- Scope-based authorization - Both OR and AND logic
- Role-based authorization - Both OR and AND logic
- Permission-based authorization - Including method-level permissions
- Mixed authorization - Combining scopes, roles, and permissions
- Object-level permissions - Resource ownership checks

## Quick Start

### Using Make (Recommended)

```bash
cd example

# Complete setup (creates .env, installs dependencies, runs migrations)
make setup

# Edit .env with your jwtforge.dev domain
nano .env  # or use your preferred editor

# Start development server
make run
```

### Manual Setup

If you prefer not to use Make:

```bash
cd example

# 1. Create environment file
cp .env.example .env

# 2. Install dependencies
pip install -r requirements.txt

# 3. Edit .env with your configuration
nano .env

# 4. Run migrations
python manage.py makemigrations
python manage.py migrate

# 5. Create superuser (optional)
python manage.py createsuperuser

# 6. Start server
python manage.py runserver
```

## Makefile Commands

The example includes a Makefile with helpful commands:

```bash
make help            # Show all available commands
make setup           # Complete setup (env, install, migrate)
make install         # Install Python dependencies
make migrate         # Run database migrations
make migrations      # Create new migrations
make superuser       # Create Django superuser
make run             # Start development server
make shell           # Open Django shell
make check           # Run Django system checks
make clean           # Remove generated files
```


## Testing with Postman

Import the `Axioms_DRF_Example.postman_collection.json` file into Postman.



jwtforge.dev provides an API endpoint to generate JWT tokens:

Endpoint: `POST https://{your-domain}.jwtforge.dev/api/token`

Request Body:
```json
{
    "aud": "https://api.example.com",
    "sub": "user123",
    "scope": "openid read:messages",
    "roles": ["admin"],
    "permissions": ["create:articles"]
}
```

Response:
```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

The Postman collection includes pre-configured requests that:
1. Call the jwtforge.dev token endpoint
2. Automatically extract the `access_token` from the response
3. Save it to a collection variable for use in subsequent requests

## Configuration Options

The application supports various axioms-drf configuration options in `core/settings.py`:

### Required Settings

```python
# Required
AXIOMS_AUDIENCE = 'https://api.example.com'

# At least one of these is required:
AXIOMS_DOMAIN = 'jwtforge.dev'
# OR
AXIOMS_ISS_URL = 'https://jwtforge.dev'
# OR
AXIOMS_JWKS_URL = 'https://jwtforge.dev/.well-known/jwks.json'
```

### Optional Settings

```python
# Custom claim names for scopes, roles, permissions
AXIOMS_SCOPE_CLAIMS = ['scope', 'scp']
AXIOMS_ROLES_CLAIMS = ['roles', 'https://example.com/roles']
AXIOMS_PERMISSIONS_CLAIMS = ['permissions', 'https://example.com/permissions']

# Safe HTTP methods that bypass authentication (default: HEAD, OPTIONS)
AXIOMS_SAFE_METHODS = ('HEAD', 'OPTIONS', 'GET')
```

## Troubleshooting

### Token Validation Fails

1. Check audience claim: Ensure `AXIOMS_AUDIENCE` in `.env` matches the `aud` claim in your token
2. Check issuer: Ensure `AXIOMS_DOMAIN` matches your jwtforge.dev domain
3. Check token expiration: jwtforge.dev tokens expire after 1 hour by default
4. Check JWKS URL: The middleware must be able to fetch the JWKS from your domain

### Authorization Fails (403)

1. Verify token claims: Check that your token includes the required scopes/roles/permissions
2. Check spelling: Scope, role, and permission names are case-sensitive
3. Review logic: Some endpoints require ALL claims (AND logic), others require ANY (OR logic)

### Database Errors

If you see database errors:
```bash
python manage.py migrate
```

## Support

For issues with:
- `axioms-drf-py` library: https://github.com/axioms-io/axioms-drf-py/issues
- Django REST Framework: https://www.django-rest-framework.org/

## Additional Resources

- [axioms-drf-py Documentation](https://github.com/axioms-io/axioms-drf-py)
- [Django REST Framework Documentation](https://www.django-rest-framework.org/)
- [JWT.io](https://jwt.io/) - JWT debugger
- [JWTForge](https://jwtforge.dev) - JWT token generation service
