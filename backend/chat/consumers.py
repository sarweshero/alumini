import json
import traceback
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['room_id']
        self.room_group_name = f'chat_{self.room_id}'

        token_key = self.scope['query_string'].decode().split('token=')[-1]
        user = await self.get_user_from_token(token_key)
        
        if not user:
            await self.close(code=4001)  # Authentication failed
            return

        self.scope['user'] = user
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            print("Received payload:", text_data)
            text_data_json = json.loads(text_data)
            if 'content' not in text_data_json:
                raise KeyError("'content' field is missing in payload")
            content = text_data_json['content']
            
            message = await self.save_message(content)
            
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': {
                        'id': str(message.id),
                        'content': message.content,
                        'sender': {
                            'username': message.sender.username,
                            'first_name': message.sender.first_name,
                            'last_name': message.sender.last_name
                        },
                        'timestamp': message.timestamp.isoformat()
                    }
                }
            )
        except KeyError:
            print("Invalid message format: missing 'content' field")
            await self.close(code=1011)
        except Exception as e:
            print(f"Error in receive: {str(e)}")
            traceback.print_exc()
            await self.close(code=1011)

    @database_sync_to_async
    def save_message(self, content):
        print("Saving message for room:", self.room_id)
        print("User in scope:", self.scope.get("user"))
        try:
            room = ChatRoom.objects.get(id=self.room_id)
        except ChatRoom.DoesNotExist:
            raise Exception(f"ChatRoom with id {self.room_id} does not exist.")
        UserModel = get_user_model()
        user = self.scope["user"]
        if hasattr(user, "_wrapped"):
            user = user._wrapped
        try:
            user_instance = UserModel.objects.get(pk=user.pk)
        except Exception as e:
            raise Exception(f"Failed to load user from pk {user.pk}: {str(e)}")
        message = Message.objects.create(
            chat_room=room,
            sender=user_instance,
            content=content
        )
        return message

    @database_sync_to_async
    def get_user_from_token(self, token_key):
        try:
            token = Token.objects.get(key=token_key)
            return get_user_model().objects.get(pk=token.user.pk)
        except Token.DoesNotExist:
            return None