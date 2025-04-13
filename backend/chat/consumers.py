import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        self.room_group_name = f"chat_{self.room_id}"
        # Accept the connection and add this channel to the group.
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    # Handle messages received from the WebSocket.
    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data.get("message")
        if message:
            user = self.scope["user"]
            chat_room = await self.get_chat_room(self.room_id)
            msg_obj = await self.create_message(chat_room, user, message)
            # Broadcast the message to all in the room.
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_message",
                    "message": message,
                    "sender": user.username,
                    "sender_full": f"{user.first_name} {user.last_name}",
                    "timestamp": str(msg_obj.timestamp),
                },
            )

    async def chat_message(self, event):
        # Send the broadcast message to WebSocket.
        await self.send(text_data=json.dumps(event))

    @database_sync_to_async
    def get_chat_room(self, room_id):
        return ChatRoom.objects.get(id=room_id)

    @database_sync_to_async
    def create_message(self, chat_room, user, message):
        return Message.objects.create(chat_room=chat_room, sender=user, content=message)