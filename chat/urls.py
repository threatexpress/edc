# chat/urls.py

from django.urls import path
from . import views

app_name = 'chat'

urlpatterns = [
    # URL pattern for the chat room (e.g., /chat/)
    path('', views.chat_room, name='room'),
]