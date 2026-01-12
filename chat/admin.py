# chat/admin.py

from django.contrib import admin
from .models import ChatMessage

@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'content_snippet')
    list_filter = ('timestamp', 'user')
    search_fields = ('user__username', 'content')
    readonly_fields = ('user', 'timestamp')
    fields = ('timestamp', 'user', 'content')

    def content_snippet(self, obj):
        return obj.content[:100] + '...' if len(obj.content) > 100 else obj.content
    content_snippet.short_description = 'Message'