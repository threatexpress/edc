# chat/views.py

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def chat_room(request):
    """
    Renders chat room.
    """
    return render(request, 'chat/room.html', {
        'current_user': request.user.username
    })