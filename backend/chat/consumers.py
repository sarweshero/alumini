import json
from channels.generic.websocket import AsyncWebsocketConsumer

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
        sender = data.get("sender")
        
        # Broadcast message to room group along with sender info
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "chat_message",
                "message": message,
                "sender": sender,
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
