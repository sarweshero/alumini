from rest_framework import serializers
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name']

class MessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'sender', 'content', 'timestamp']

class ChatRoomSerializer(serializers.ModelSerializer):
    last_message = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    time = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ['id', 'name', 'last_message', 'time']

    def get_last_message(self, obj):
        last_msg = obj.messages.last()
        return last_msg.content if last_msg else ''

    def get_name(self, obj):
        request_user = self.context['request'].user
        other_users = obj.users.exclude(id=request_user.id)
        if other_users.exists():
            other_user = other_users.first()
            return f"{other_user.first_name} {other_user.last_name}".strip() or other_user.username
        return "Unnamed Chat"

    def get_time(self, obj):
        last_msg = obj.messages.last()
        return last_msg.timestamp.isoformat() if last_msg else obj.created_at.isoformat()