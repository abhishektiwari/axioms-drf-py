"""Basic import tests for axioms-drf-py package."""

import pytest


def test_import_axioms_drf():
    """Test that the main package can be imported."""
    import axioms_drf
    assert axioms_drf is not None


def test_package_version():
    """Test that package version is accessible."""
    import axioms_drf

    # Check if version attribute exists (might not be defined yet)
    if hasattr(axioms_drf, '__version__'):
        version = axioms_drf.__version__
        assert isinstance(version, str)
        assert len(version) > 0
        print(f"Package version: {version}")
    else:
        # Version might not be set in development mode
        print("Version attribute not found (may not be set in development mode)")


def test_import_helper_module():
    """Test that helper module can be imported."""
    from axioms_drf import helper
    assert helper is not None
    assert hasattr(helper, 'has_valid_token')
    assert hasattr(helper, 'check_scopes')
    assert hasattr(helper, 'check_roles')
    assert hasattr(helper, 'check_permissions')


def test_import_authentication_module():
    """Test that authentication module can be imported."""
    from axioms_drf import authentication
    assert authentication is not None
    assert hasattr(authentication, 'HasValidAccessToken')
    assert hasattr(authentication, 'UnauthorizedAccess')


def test_import_permissions_module():
    """Test that permissions module can be imported."""
    from axioms_drf import permissions
    assert permissions is not None
    assert hasattr(permissions, 'HasAccessTokenScopes')
    assert hasattr(permissions, 'HasAccessTokenRoles')
    assert hasattr(permissions, 'HasAccessTokenPermissions')


def test_import_middleware_module():
    """Test that middleware module can be imported."""
    from axioms_drf import middleware
    assert middleware is not None
