# edc_project/asgi.py

import os
from django.core.asgi import get_asgi_application
import django

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'edc_project.settings')
django.setup() # Initialize Django

# Import Channels components AFTER setup
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack 
from django.urls import path
import chat.routing

# The standard Django HTTP application
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    # Use AuthMiddlewareStack to inject the authenticated user into the WebSocket scope
    "websocket": AuthMiddlewareStack(
        URLRouter(
            chat.routing.websocket_urlpatterns
        )
    ),
})