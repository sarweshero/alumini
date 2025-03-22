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
        user1 = self.scope['user'].username  # Corrected 'slcope' to 'scope'
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
            message_content = data.get('content')  # Get content instead of message
            sender = self.scope['user']
            receiver = await self.get_receiver_user()
            
            # Save message and get instance
            msg = await self.save_message(sender, receiver, message_content)
            
            # Broadcast with full details
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'id': msg.id,
                    'sender': f"{sender.first_name} {sender.last_name}",
                    'senderUsername': sender.username,
                    'text': msg.content,
                    'timestamp': msg.timestamp.isoformat()
                }
            )

    async def chat_message(self, event):
        # Send structured message to frontend
        await self.send(text_data=json.dumps({
            'command': 'new_message',
            'id': event['id'],
            'sender': event['sender'],
            'senderUsername': event['senderUsername'],
            'text': event['text'],
            'time': event['timestamp']
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
        ).order_by('timestamp').select_related('sender', 'receiver')
        
        return [
            {
                'id': msg.id,
                'sender': f"{msg.sender.first_name} {msg.sender.last_name}",
                'senderUsername': msg.sender.username,
                'text': msg.content,
                'time': msg.timestamp.isoformat()
            }
            for msg in messages
        ]