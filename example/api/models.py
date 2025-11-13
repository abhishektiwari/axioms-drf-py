"""API models."""

from django.db import models


class Article(models.Model):
    """Sample article model for demonstrating object-level permissions."""

    title = models.CharField(max_length=200)
    content = models.TextField()
    author_sub = models.CharField(max_length=255, help_text="JWT sub claim of the author")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
