from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import ChatRoom, ChatMessage

User = get_user_model()

class ChatRoomSerializer(serializers.ModelSerializer):
    participants = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='username'
    )
    
    class Meta:
        model = ChatRoom
        fields = ['id', 'name', 'participants', 'created_at']

class ChatMessageSerializer(serializers.ModelSerializer):
    sender = serializers.SerializerMethodField()

    class Meta:
        model = ChatMessage
        fields = ['id', 'room', 'sender', 'content', 'timestamp']
        read_only_fields = ['room', 'sender', 'timestamp']

    def get_sender(self, obj):
        # Return sender's profile info from the user model
        profile = getattr(obj.sender, 'profile', None)
        if profile:
            return {
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "username": obj.sender.username
            }
        return {"username": obj.sender.username}
