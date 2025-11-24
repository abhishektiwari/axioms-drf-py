"""Django AppConfig classes for automatic JWKS manager lifecycle management.

These apps handle initialization and shutdown of the JWKS manager automatically.
Users can simply add the appropriate app to their INSTALLED_APPS.

For standard Django/WSGI applications:
    INSTALLED_APPS = [
        'axioms_drf.apps.JWKSManagerWSGIConfig',
        # ... other apps
    ]

For Django ASGI applications:
    INSTALLED_APPS = [
        'axioms_drf.apps.JWKSManagerASGIConfig',
        # ... other apps
    ]
"""

import atexit
from django.apps import AppConfig


class JWKSManagerWSGIConfig(AppConfig):
    """AppConfig for JWKS manager with background refresh for WSGI applications.

    This app automatically initializes the JWKS manager with background refresh
    on Django startup and properly shuts it down on application exit.

    Usage:
        Add to INSTALLED_APPS in settings.py:

        INSTALLED_APPS = [
            'axioms_drf.apps.JWKSManagerWSGIConfig',
            # ... other apps
        ]

    Configuration (optional):
        AXIOMS_JWKS_REFRESH_INTERVAL = 3600  # Refresh every 1hr (default)
        AXIOMS_JWKS_CACHE_TTL = 7200         # Cache for 2hrs (default)

    For standard Django/WSGI applications. Use JWKSManagerASGIConfig for ASGI.
    """

    name = "axioms_drf"
    label = "axioms_drf_jwks_wsgi"
    verbose_name = "Axioms DRF JWKS Manager (WSGI)"

    def ready(self):
        """Initialize JWKS manager on application startup."""
        from axioms_core import (
            initialize_jwks_manager,
            shutdown_jwks_manager,
            AxiomsConfig,
        )
        from django.conf import settings

        # Build Axioms configuration from Django settings
        config = AxiomsConfig(
            AXIOMS_JWKS_URL=getattr(settings, "AXIOMS_JWKS_URL", None),
            AXIOMS_DOMAIN=getattr(settings, "AXIOMS_DOMAIN", None),
            AXIOMS_ISS_URL=getattr(settings, "AXIOMS_ISS_URL", None),
        )

        # Get refresh intervals from settings with sensible defaults
        refresh_interval = getattr(settings, "AXIOMS_JWKS_REFRESH_INTERVAL", 3600)
        cache_ttl = getattr(settings, "AXIOMS_JWKS_CACHE_TTL", 7200)

        # Initialize JWKS manager with background refresh thread
        initialize_jwks_manager(
            config=config,
            refresh_interval=refresh_interval,
            cache_ttl=cache_ttl,
        )

        # Register shutdown handler to cleanup background thread
        atexit.register(shutdown_jwks_manager)


class JWKSManagerASGIConfig(AppConfig):
    """AppConfig for JWKS manager with background refresh for ASGI applications.

    This app automatically initializes the async JWKS manager with background
    refresh on Django startup and properly shuts it down on application exit.

    Usage:
        Add to INSTALLED_APPS in settings.py:

        INSTALLED_APPS = [
            'axioms_drf.apps.JWKSManagerASGIConfig',
            # ... other apps
        ]

    Configuration (optional):
        AXIOMS_JWKS_REFRESH_INTERVAL = 3600  # Refresh every 1hr (default)
        AXIOMS_JWKS_CACHE_TTL = 7200         # Cache for 2hrs (default)

    For Django ASGI applications. Use JWKSManagerWSGIConfig for WSGI.
    """

    name = "axioms_drf"
    label = "axioms_drf_jwks_asgi"
    verbose_name = "Axioms DRF JWKS Manager (ASGI)"

    def ready(self):
        """Initialize async JWKS manager on application startup."""
        import asyncio
        from axioms_core import (
            initialize_async_jwks_manager,
            shutdown_async_jwks_manager,
            AxiomsConfig,
        )
        from django.conf import settings

        # Build Axioms configuration from Django settings
        config = AxiomsConfig(
            AXIOMS_JWKS_URL=getattr(settings, "AXIOMS_JWKS_URL", None),
            AXIOMS_DOMAIN=getattr(settings, "AXIOMS_DOMAIN", None),
            AXIOMS_ISS_URL=getattr(settings, "AXIOMS_ISS_URL", None),
        )

        # Get refresh intervals from settings with sensible defaults
        refresh_interval = getattr(settings, "AXIOMS_JWKS_REFRESH_INTERVAL", 3600)
        cache_ttl = getattr(settings, "AXIOMS_JWKS_CACHE_TTL", 7200)

        # Initialize async JWKS manager with background refresh task
        # We need to run this in an event loop
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            # Create new event loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Schedule initialization as a coroutine
        async def _initialize():
            await initialize_async_jwks_manager(
                config=config,
                refresh_interval=refresh_interval,
                cache_ttl=cache_ttl,
            )

        # Run initialization
        loop.run_until_complete(_initialize())

        # Register async shutdown handler
        def _shutdown():
            loop.run_until_complete(shutdown_async_jwks_manager())

        atexit.register(_shutdown)
