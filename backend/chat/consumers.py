import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import ChatRoom, ChatMessage
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        self.room_group_name = f"chat_{self.room_id}"
        
        await self.accept()
        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

    async def disconnect(self, _close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data.get("message")
        sender_username = data.get("sender")

        # Get sender user object
        sender = await self.get_user(sender_username)
        if not sender:
            return

        # Save message to database
        room = await self.get_room(self.room_id)
        if room:
            await self.save_message(room, sender, message)

        # Broadcast message to room group along with sender info
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "chat_message",
                "message": message,
                "sender": sender_username,
            }
        )

    async def chat_message(self, event):
        message = event["message"]
        sender = event["sender"]
        # Send message to WebSocket for all clients (including sender)
        await self.send(text_data=json.dumps({
            "message": message,
            "sender": sender,
        }))

    @database_sync_to_async
    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def get_room(self, room_id):
        try:
            return ChatRoom.objects.get(id=room_id)
        except ChatRoom.DoesNotExist:
            return None

    @database_sync_to_async
    def save_message(self, room, sender, message):
        ChatMessage.objects.create(room=room, sender=sender, content=message)
