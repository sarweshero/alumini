from rest_framework import permissions
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message
from .serializers import ChatRoomSerializer, MessageSerializer, UserSerializer

User = get_user_model()

# Removed ChatRoomListCreateAPIView, MessageListCreateAPIView, MessageDetailAPIView, and ContactSearchAPIView.
# WebSocket consumers are used instead.