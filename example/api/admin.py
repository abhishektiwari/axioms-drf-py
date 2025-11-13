"""Admin configuration for API app."""

from django.contrib import admin
from .models import Article


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    """Admin interface for Article model."""

    list_display = ['title', 'author_sub', 'created_at', 'updated_at']
    list_filter = ['created_at', 'updated_at']
    search_fields = ['title', 'content', 'author_sub']
    readonly_fields = ['created_at', 'updated_at']
