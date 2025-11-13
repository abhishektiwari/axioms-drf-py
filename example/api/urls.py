"""API URL configuration."""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'articles', views.ArticleViewSet, basename='article')

urlpatterns = [
    # Public endpoint
    path('public', views.PublicView.as_view(), name='public'),

    # Authentication only
    path('authenticated', views.AuthenticatedView.as_view(), name='authenticated'),

    # Scope-based authorization
    path('scope-protected', views.ScopeProtectedView.as_view(), name='scope-protected'),
    path('multiple-scopes', views.MultipleScopesView.as_view(), name='multiple-scopes'),
    path('all-scopes', views.AllScopesView.as_view(), name='all-scopes'),

    # Role-based authorization
    path('role-protected', views.RoleProtectedView.as_view(), name='role-protected'),
    path('all-roles', views.AllRolesView.as_view(), name='all-roles'),

    # Permission-based authorization
    path('permission-protected', views.PermissionProtectedView.as_view(), name='permission-protected'),
    path('multiple-permissions', views.MultiplePermissionsView.as_view(), name='multiple-permissions'),

    # Mixed authorization
    path('mixed-authorization', views.MixedAuthorizationView.as_view(), name='mixed-authorization'),

    # Include router URLs for ArticleViewSet
    path('', include(router.urls)),
]
