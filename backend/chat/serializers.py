from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "first_name", "last_name", "profile_photo")

class MessageSerializer(serializers.ModelSerializer):
    text = serializers.CharField(source="content")
    time = serializers.DateTimeField(source="timestamp", format="%H:%M")
    sender = UserSerializer(read_only=True)

    class Meta:
        model = Message
        fields = ("id", "text", "sender", "time")

class ChatRoomSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    lastMessage = serializers.SerializerMethodField()
    lastMessageTime = serializers.SerializerMethodField()
    unreadCount = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ("id", "name", "lastMessage", "lastMessageTime", "unreadCount", "avatar")

    def get_name(self, obj):
        request = self.context.get("request")
        if request:
            other_users = obj.users.exclude(id=request.user.id)
            usernames = [f"{u.first_name} {u.last_name}".strip() or u.username for u in other_users]
        else:
            usernames = [user.username for user in obj.users.all()]
        return ", ".join(usernames) if usernames else "Chat Room"

    def get_lastMessage(self, obj):
        last_message = obj.messages.order_by("-timestamp").first()
        return last_message.content if last_message else ""

    def get_lastMessageTime(self, obj):
        last_message = obj.messages.order_by("-timestamp").first()
        return last_message.timestamp if last_message else obj.created_at

    def get_unreadCount(self, obj):
        # Optional: implement unread logic, for now return 0
        return 0

    def get_avatar(self, obj):
        # Optional: implement avatar logic, for now return None
        return None