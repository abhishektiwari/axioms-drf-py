"""API serializers."""

from rest_framework import serializers
from .models import Article


class ArticleSerializer(serializers.ModelSerializer):
    """Serializer for Article model."""

    class Meta:
        model = Article
        fields = ['id', 'title', 'content', 'author_sub', 'created_at', 'updated_at']
        read_only_fields = ['id', 'author_sub', 'created_at', 'updated_at']
