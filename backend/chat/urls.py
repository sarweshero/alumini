from django.urls import path, re_path
from .views import *

urlpatterns = [
    path("rooms/", ChatRoomListCreateAPIView.as_view(), name="chat_rooms"),
    path("rooms/<uuid:room_id>/messages/", MessageListCreateAPIView.as_view(), name="chat_messages"),
    path("rooms/<uuid:room_id>/messages/<uuid:id>/", MessageDetailAPIView.as_view(), name="message_detail"),
    path("search/", ContactSearchAPIView.as_view(), name="contact_search"),
]