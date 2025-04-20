from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path
from chat import consumers
from .chat.middleware import TokenAuthMiddlewareStack

application = ProtocolTypeRouter({
    "websocket": TokenAuthMiddlewareStack(
        URLRouter([
            path("ws/chat/<str:room_id>/", consumers.ChatConsumer.as_asgi()),
        ])
    ),
})