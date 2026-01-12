# chat/models.py (NEW)

from django.db import models
from django.conf import settings

class ChatMessage(models.Model):
    """Store a single chat message."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, # If the user is deleted, their messages are too
        related_name='chat_messages'
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    content = models.TextField()

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M')}] {self.user.username}: {self.content[:50]}..."

    class Meta:
        verbose_name = "Chat Message"
        verbose_name_plural = "Chat Messages"
        ordering = ['timestamp']