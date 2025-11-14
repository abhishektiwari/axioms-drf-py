"""API serializers."""

from rest_framework import serializers
from .models import Article, Book


class ArticleSerializer(serializers.ModelSerializer):
    """Serializer for Article model."""

    class Meta:
        model = Article
        fields = ['id', 'title', 'content', 'author_sub', 'created_at', 'updated_at']
        read_only_fields = ['id', 'author_sub', 'created_at', 'updated_at']


class BookSerializer(serializers.ModelSerializer):
    """Serializer for Book model."""

    class Meta:
        model = Book
        fields = ['id', 'title', 'author', 'isbn', 'published_date', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
