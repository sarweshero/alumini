from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ChatMessage as Message

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name']

class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.username', read_only=True)
    receiver_name = serializers.CharField(source='receiver.username', read_only=True)
    
    class Meta:
        model = Message
        fields = ['id', 'content', 'timestamp', 'sender', 'sender_name', 'receiver', 'receiver_name']