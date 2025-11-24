"""Tests for Django AppConfig classes that manage JWKS manager lifecycle."""

import pytest
from unittest.mock import MagicMock, patch, call
from django.test import override_settings


class TestJWKSManagerWSGIConfig:
    """Test JWKSManagerWSGIConfig AppConfig."""

    def test_app_config_attributes(self):
        """Test that app config has correct attributes."""
        from axioms_drf.apps import JWKSManagerWSGIConfig
        import axioms_drf

        config = JWKSManagerWSGIConfig('axioms_drf', axioms_drf)

        assert config.name == 'axioms_drf'
        assert config.label == 'axioms_drf_jwks_wsgi'
        assert config.verbose_name == 'Axioms DRF JWKS Manager (WSGI)'

    @override_settings(
        AXIOMS_JWKS_URL='https://test.com/.well-known/jwks.json',
        AXIOMS_ISS_URL='https://test.com',
        AXIOMS_DOMAIN=None,
        AXIOMS_JWKS_REFRESH_INTERVAL=1800,
        AXIOMS_JWKS_CACHE_TTL=3600,
    )
    @patch('axioms_core.initialize_jwks_manager')
    @patch('atexit.register')
    def test_ready_initializes_jwks_manager_with_custom_settings(
        self, mock_atexit, mock_initialize
    ):
        """Test that ready() initializes JWKS manager with custom settings."""
        from axioms_drf.apps import JWKSManagerWSGIConfig
        from axioms_core import AxiomsConfig
        import axioms_drf

        config = JWKSManagerWSGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Verify initialize_jwks_manager was called
        assert mock_initialize.call_count == 1

        # Get the call arguments
        call_args = mock_initialize.call_args

        # Check AxiomsConfig was passed correctly
        axioms_config = call_args[1]['config']
        assert isinstance(axioms_config, AxiomsConfig)
        assert axioms_config.AXIOMS_JWKS_URL == 'https://test.com/.well-known/jwks.json'
        assert axioms_config.AXIOMS_ISS_URL == 'https://test.com'

        # Check refresh intervals
        assert call_args[1]['refresh_interval'] == 1800
        assert call_args[1]['cache_ttl'] == 3600

        # Verify atexit.register was called for shutdown
        mock_atexit.assert_called_once()

    @override_settings(
        AXIOMS_DOMAIN='test.auth.com',
        AXIOMS_JWKS_URL=None,
        AXIOMS_ISS_URL=None,
    )
    @patch('axioms_core.initialize_jwks_manager')
    @patch('atexit.register')
    def test_ready_uses_default_refresh_intervals(self, mock_atexit, mock_initialize):
        """Test that ready() uses default refresh intervals when not configured."""
        from axioms_drf.apps import JWKSManagerWSGIConfig
        import axioms_drf

        config = JWKSManagerWSGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Get the call arguments
        call_args = mock_initialize.call_args

        # Check default refresh intervals (3600 and 7200)
        assert call_args[1]['refresh_interval'] == 3600
        assert call_args[1]['cache_ttl'] == 7200

        # Verify atexit.register was called
        mock_atexit.assert_called_once()

    @patch('axioms_core.initialize_jwks_manager')
    @patch('atexit.register')
    @patch('axioms_core.shutdown_jwks_manager')
    def test_ready_registers_shutdown_handler(
        self, mock_shutdown, mock_atexit, mock_initialize
    ):
        """Test that ready() registers shutdown handler with atexit."""
        from axioms_drf.apps import JWKSManagerWSGIConfig
        import axioms_drf

        config = JWKSManagerWSGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Verify atexit.register was called with shutdown_jwks_manager
        mock_atexit.assert_called_once_with(mock_shutdown)


class TestJWKSManagerASGIConfig:
    """Test JWKSManagerASGIConfig AppConfig."""

    def test_app_config_attributes(self):
        """Test that app config has correct attributes."""
        from axioms_drf.apps import JWKSManagerASGIConfig
        import axioms_drf

        config = JWKSManagerASGIConfig('axioms_drf', axioms_drf)

        assert config.name == 'axioms_drf'
        assert config.label == 'axioms_drf_jwks_asgi'
        assert config.verbose_name == 'Axioms DRF JWKS Manager (ASGI)'

    @override_settings(
        AXIOMS_JWKS_URL='https://test.com/.well-known/jwks.json',
        AXIOMS_ISS_URL='https://test.com',
        AXIOMS_DOMAIN=None,
        AXIOMS_JWKS_REFRESH_INTERVAL=1800,
        AXIOMS_JWKS_CACHE_TTL=3600,
    )
    @patch('asyncio.get_event_loop')
    @patch('axioms_core.initialize_async_jwks_manager')
    @patch('atexit.register')
    def test_ready_initializes_async_jwks_manager_with_custom_settings(
        self, mock_atexit, mock_initialize_async, mock_get_loop
    ):
        """Test that ready() initializes async JWKS manager with custom settings."""
        from axioms_drf.apps import JWKSManagerASGIConfig
        from axioms_core import AxiomsConfig
        import axioms_drf

        # Mock event loop
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop

        config = JWKSManagerASGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Verify event loop was obtained
        mock_get_loop.assert_called_once()

        # Verify run_until_complete was called to initialize
        assert mock_loop.run_until_complete.call_count >= 1

        # Verify atexit.register was called for shutdown
        mock_atexit.assert_called_once()

    @override_settings(
        AXIOMS_DOMAIN='test.auth.com',
        AXIOMS_JWKS_URL=None,
        AXIOMS_ISS_URL=None,
    )
    @patch('asyncio.get_event_loop')
    @patch('asyncio.new_event_loop')
    @patch('asyncio.set_event_loop')
    @patch('axioms_core.initialize_async_jwks_manager')
    @patch('atexit.register')
    def test_ready_creates_new_event_loop_on_runtime_error(
        self, mock_atexit, mock_initialize_async, mock_set_loop,
        mock_new_loop, mock_get_loop
    ):
        """Test that ready() creates new event loop when RuntimeError occurs."""
        from axioms_drf.apps import JWKSManagerASGIConfig
        import axioms_drf

        # Mock get_event_loop to raise RuntimeError (no loop exists)
        mock_get_loop.side_effect = RuntimeError("No event loop")

        # Mock new event loop
        mock_loop = MagicMock()
        mock_new_loop.return_value = mock_loop

        config = JWKSManagerASGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Verify new event loop was created and set
        mock_get_loop.assert_called_once()
        mock_new_loop.assert_called_once()
        mock_set_loop.assert_called_once_with(mock_loop)

        # Verify initialization was called on the new loop
        assert mock_loop.run_until_complete.call_count >= 1

        # Verify atexit.register was called
        mock_atexit.assert_called_once()

    @override_settings(
        AXIOMS_JWKS_URL='https://test.com/.well-known/jwks.json',
        AXIOMS_ISS_URL='https://test.com',
    )
    @patch('asyncio.get_event_loop')
    @patch('axioms_core.initialize_async_jwks_manager')
    @patch('atexit.register')
    @patch('axioms_core.shutdown_async_jwks_manager')
    def test_ready_registers_async_shutdown_handler(
        self, mock_shutdown_async, mock_atexit, mock_initialize_async, mock_get_loop
    ):
        """Test that ready() registers async shutdown handler with atexit."""
        from axioms_drf.apps import JWKSManagerASGIConfig
        import axioms_drf

        # Mock event loop
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop

        config = JWKSManagerASGIConfig('axioms_drf', axioms_drf)
        config.ready()

        # Verify atexit.register was called
        mock_atexit.assert_called_once()

        # Get the shutdown function that was registered
        shutdown_func = mock_atexit.call_args[0][0]

        # Call the shutdown function and verify it runs shutdown_async_jwks_manager
        shutdown_func()

        # The shutdown function should call loop.run_until_complete with shutdown_async_jwks_manager
        assert mock_loop.run_until_complete.call_count >= 1


class TestAppConfigImports:
    """Test that app configs can be imported and used in INSTALLED_APPS."""

    def test_import_wsgi_config(self):
        """Test that JWKSManagerWSGIConfig can be imported."""
        from axioms_drf.apps import JWKSManagerWSGIConfig

        assert JWKSManagerWSGIConfig is not None
        assert hasattr(JWKSManagerWSGIConfig, 'ready')

    def test_import_asgi_config(self):
        """Test that JWKSManagerASGIConfig can be imported."""
        from axioms_drf.apps import JWKSManagerASGIConfig

        assert JWKSManagerASGIConfig is not None
        assert hasattr(JWKSManagerASGIConfig, 'ready')

    def test_wsgi_config_is_app_config(self):
        """Test that JWKSManagerWSGIConfig is a Django AppConfig."""
        from django.apps import AppConfig
        from axioms_drf.apps import JWKSManagerWSGIConfig

        assert issubclass(JWKSManagerWSGIConfig, AppConfig)

    def test_asgi_config_is_app_config(self):
        """Test that JWKSManagerASGIConfig is a Django AppConfig."""
        from django.apps import AppConfig
        from axioms_drf.apps import JWKSManagerASGIConfig

        assert issubclass(JWKSManagerASGIConfig, AppConfig)
