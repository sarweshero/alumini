import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import ChatRoom, Message

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        if not self.user.is_authenticated:
            await self.close()
            return
        # Accept "room_id" as a URL kwarg; if not provided, use a default group.
        self.room_id = self.scope.get("url_route", {}).get("kwargs", {}).get("room_id")
        self.room_group_name = f"chat_{self.room_id}" if self.room_id else "all_chat"
        # If a room_id is provided, verify that the chat room exists and the user is a member.
        if self.room_id:
            room = await self.get_chat_room(self.room_id)
            if not room:
                await self.close()
                return
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        action = data.get("action")
        if action == "create_room":
            target_user_id = data.get("target_user_id")
            room, created = await self.get_or_create_chat_room(self.user, target_user_id)
            if room:
                # Optionally join the newly created room's group.
                self.room_id = room.id
                self.room_group_name = f"chat_{self.room_id}"
                await self.channel_layer.group_add(self.room_group_name, self.channel_name)
                await self.send(json.dumps({"action": "room_created", "room_id": room.id}))
            else:
                await self.send(json.dumps({"error": "Target user not found."}))
        elif action == "send_message":
            message_text = data.get("message")
            if self.room_id and message_text:
                message = await self.create_message(self.user, self.room_id, message_text)
                # Broadcast the message to the room group.
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        "type": "chat_message",
                        "message": message_text,
                        "sender": self.user.username,
                        "message_id": message.id,
                    },
                )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event))

    @database_sync_to_async
    def get_chat_room(self, room_id):
        try:
            return ChatRoom.objects.get(id=room_id, users=self.user)
        except ChatRoom.DoesNotExist:
            return None

    @database_sync_to_async
    def get_or_create_chat_room(self, user, target_user_id):
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            return None, False
        qs = ChatRoom.objects.filter(users=user).filter(users=target_user)
        if qs.exists():
            return qs.first(), False
        room = ChatRoom.objects.create()
        room.users.add(user, target_user)
        return room, True

    @database_sync_to_async
    def create_message(self, user, room_id, message_text):
        chat_room = ChatRoom.objects.get(id=room_id, users=user)
        # Assumes Message model has a field "content" for the message text.
        message = Message.objects.create(chat_room=chat_room, sender=user, content=message_text)
        return message