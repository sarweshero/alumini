import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from django.db.models import Q
from .models import ChatMessage  # ensure your model name matches
from asgiref.sync import sync_to_async

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        user1 = self.slcope['user'].username 
        user2 = self.room_name  # here the room name represents the receiver's username
        self.room_group_name = f"chat_{''.join(sorted([user1, user2]))}"
        
        # Join room group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()
        # Fetch and send previous messages for the room
        messages = await self.fetch_messages(user1, user2)
        await self.send(text_data=json.dumps({
            'command': 'messages',
            'messages': messages,
        }))

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        command = data.get('command')
        if command == 'new_message':
            message = data.get('message')
            sender = self.scope['user']
            receiver = await self.get_receiver_user()
            await self.save_message(sender, receiver, message)
            # Broadcast the new message to everyone in the room group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'sender': sender.username,
                    'receiver': receiver.username,
                    'message': message
                }
            )
        # You can add more commands here if needed.

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'command': 'new_message',
            'sender': event['sender'],
            'receiver': event['receiver'],
            'message': event['message']
        }))

    @sync_to_async
    def save_message(self, sender, receiver, message):
        ChatMessage.objects.create(sender=sender, receiver=receiver, content=message)

    @sync_to_async
    def get_receiver_user(self):
        # Since room_name is the receiver's username
        return User.objects.get(username=self.room_name)

    @sync_to_async
    def fetch_messages(self, user1, user2):
        messages = ChatMessage.objects.filter(
            Q(sender__username=user1, receiver__username=user2) |
            Q(sender__username=user2, receiver__username=user1)
        ).order_by('timestamp')
        return [
            {
                'sender': msg.sender.username,
                'receiver': msg.receiver.username,
                'content': msg.content,
                'timestamp': msg.timestamp.isoformat()
            }
            for msg in messages
        ]