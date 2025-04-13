from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "first_name", "last_name")

class MessageSerializer(serializers.ModelSerializer):
    # Rename fields to match frontend expectations.
    text = serializers.CharField(source="content")
    time = serializers.DateTimeField(source="timestamp", format="%H:%M")
    sender = UserSerializer(read_only=True)
    
    class Meta:
        model = Message
        fields = ("id", "text", "sender", "time")

class ChatRoomSerializer(serializers.ModelSerializer):
    # Include messages for a detailed room view.
    messages = MessageSerializer(many=True, read_only=True)
    # Generate a chat name based on the participants (excluding the current user)
    name = serializers.SerializerMethodField()
    # Show the last message content (if available)
    lastMessage = serializers.SerializerMethodField()
    # Use timestamp from the last message or the room’s creation date
    time = serializers.SerializerMethodField()

    class Meta:
        model = ChatRoom
        fields = ("id", "name", "lastMessage", "time", "messages")

    def get_name(self, obj):
        request = self.context.get("request")
        if request:
            # Exclude the current user for naming purposes
            other_users = obj.users.exclude(id=request.user.id)
            usernames = [user.username for user in other_users]
        else:
            usernames = [user.username for user in obj.users.all()]
        return ", ".join(usernames) if usernames else "Chat Room"

    def get_lastMessage(self, obj):
        last_message = obj.messages.order_by("-timestamp").first()
        return last_message.content if last_message else ""

    def get_time(self, obj):
        last_message = obj.messages.order_by("-timestamp").first()
        return last_message.timestamp if last_message else obj.created_at