# chat/consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from asgiref.sync import sync_to_async
from .models import ChatMessage
import re

User = get_user_model()

# Regex for simple link detection (to support link sharing)
URL_REGEX = re.compile(
    r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
)

GLOBAL_CHAT_ROOM_NAME = "oplog_chat"

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # 1. Check for authentication (AuthMiddlewareStack handles session-based auth)
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        self.user = self.scope["user"]
        self.room_group_name = GLOBAL_CHAT_ROOM_NAME

        # 2. Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

        # 3. Load last 10 messages (or less) for new users
        recent_messages = await self.get_recent_messages()
        for message in recent_messages:
            await self.send(text_data=json.dumps(message))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        if self.scope["user"].is_anonymous:
            return

        text_data_json = json.loads(text_data)
        message = text_data_json.get('message', '').strip()

        if not message:
            return

        # 1. Save message to database (async operation)
        new_message = await self.save_message(self.user, message)

        # 2. Construct the message data for broadcast
        broadcast_data = {
            'type': 'chat_message', # Method name in this class
            'content': new_message['content'],
            'username': new_message['username'],
            'timestamp': new_message['timestamp'],
        }

        # 3. Send message to room group (broadcast)
        await self.channel_layer.group_send(
            self.room_group_name,
            broadcast_data
        )

    # Receive message from room group
    async def chat_message(self, event):
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'content': event['content'],
            'username': event['username'],
            'timestamp': event['timestamp'],
        }))

    # Helper function to save message to DB
    @sync_to_async
    def save_message(self, user, content):
        ChatMessage.objects.create(user=user, content=content)
        return {
            'content': content,
            'username': user.username,
            'timestamp': now().isoformat(),
        }

    # Helper function to fetch last 100 messages
    @sync_to_async
    def get_recent_messages(self):
        messages = ChatMessage.objects.select_related('user').order_by('-timestamp')[:100]
        result = []
        for msg in reversed(messages):
            result.append({
                'content': msg.content,
                'username': msg.user.username,
                'timestamp': msg.timestamp.isoformat(),
            })
        return result