"""Tests for object-level permissions (IsSubOwner, IsSubOwnerOrSafeOnly, IsSafeOnly).

This module tests the new object-level permission classes that check token subject
ownership and safe HTTP methods.
"""

import json
import time

from tests.conftest import generate_jwt_token

from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import (
    IsSubOwner,
    IsSubOwnerOrSafeOnly,
    IsSafeOnly,
)


# Create a simple mock model object for testing
class MockArticle:
    """Mock article object for testing object-level permissions."""

    def __init__(self, pk, author_id, title="Test Article"):
        self.pk = pk
        self.author_id = author_id
        self.title = title


class TestIsSubOwner:
    """Test IsSubOwner object-level permission."""

    def test_owner_can_access(self, factory, test_key):
        """Test that token subject matching owner attribute grants access."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        # Create view with IsSubOwner permission
        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwner]
            owner_attribute = "author_id"

            def get(self, request, pk):
                article = MockArticle(pk=pk, author_id="user123")
                self.check_object_permissions(request, article)
                return Response({"title": article.title})

        # Generate token with matching sub
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        # Create request with factory that applies middleware
        view = ArticleDetailView.as_view()
        request = factory.get("/articles/1/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request, pk=1)

        assert response.status_code == 200
        assert response.data["title"] == "Test Article"

    def test_non_owner_denied(self, factory, test_key):
        """Test that non-owner is denied access."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwner]
            owner_attribute = "author_id"

            def get(self, request, pk):
                article = MockArticle(pk=pk, author_id="user456")  # Different owner
                self.check_object_permissions(request, article)
                return Response({"title": article.title})

        # Generate token with different sub
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleDetailView.as_view()
        request = factory.get("/articles/1/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request, pk=1)

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "error" in response.data
        assert "message" in response.data
        assert "permission" in str(response.data["message"]).lower()


class TestIsSubOwnerOrSafeOnly:
    """Test IsSubOwnerOrSafeOnly object-level permission."""

    def test_anyone_can_read_safe_method(self, factory, test_key):
        """Test that any authenticated user can use safe methods."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwnerOrSafeOnly]
            owner_attribute = "author_id"
            safe_methods = ("GET", "HEAD", "OPTIONS")

            def get(self, request, pk):
                article = MockArticle(pk=pk, author_id="user456")  # Different owner
                self.check_object_permissions(request, article)
                return Response({"title": article.title})

        # Generate token with different sub
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleDetailView.as_view()
        request = factory.get("/articles/1/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request, pk=1)

        # Should succeed because GET is a safe method
        assert response.status_code == 200

    def test_owner_can_modify(self, factory, test_key):
        """Test that owner can use unsafe methods."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwnerOrSafeOnly]
            owner_attribute = "author_id"
            safe_methods = ("GET", "HEAD", "OPTIONS")

            def delete(self, request, pk):
                article = MockArticle(pk=pk, author_id="user123")  # Same owner
                self.check_object_permissions(request, article)
                return Response({"status": "deleted"})

        # Generate token with matching sub
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleDetailView.as_view()
        request = factory.delete("/articles/1/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request, pk=1)

        # Should succeed because user is owner
        assert response.status_code == 200

    def test_non_owner_denied_unsafe_method(self, factory, test_key):
        """Test that non-owner is denied unsafe methods."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwnerOrSafeOnly]
            owner_attribute = "author_id"
            safe_methods = ("GET", "HEAD", "OPTIONS")

            def delete(self, request, pk):
                article = MockArticle(pk=pk, author_id="user456")  # Different owner
                self.check_object_permissions(request, article)
                return Response({"status": "deleted"})

        # Generate token with different sub
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleDetailView.as_view()
        request = factory.delete("/articles/1/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request, pk=1)

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "error" in response.data
        assert "message" in response.data
        assert "permission" in str(response.data["message"]).lower()


class TestIsSafeOnly:
    """Test IsSafeOnly permission."""

    def test_safe_method_allowed(self, factory, test_key):
        """Test that safe methods are allowed."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleListView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSafeOnly]
            safe_methods = ("GET", "HEAD", "OPTIONS")

            def get(self, request):
                return Response({"articles": []})

        # Generate token
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleListView.as_view()
        request = factory.get("/articles/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request)

        # Should succeed because GET is safe
        assert response.status_code == 200

    def test_unsafe_method_denied(self, factory, test_key):
        """Test that unsafe methods are denied."""
        from rest_framework.response import Response
        from rest_framework.views import APIView

        class ArticleListView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSafeOnly]
            safe_methods = ("GET", "HEAD", "OPTIONS")

            def post(self, request):
                return Response({"status": "created"})

        # Generate token
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "aud": ["test-audience"],
                "iss": "https://test-domain.com",
                "exp": now + 3600,
                "iat": now,
            }
        )

        token = generate_jwt_token(test_key, claims)

        view = ArticleListView.as_view()
        request = factory.post("/articles/", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = view(request)

        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "error" in response.data
        assert "message" in response.data
        assert "permission" in str(response.data["message"]).lower()
