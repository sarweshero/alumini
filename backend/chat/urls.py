from django.urls import path
from .views import ChatRoomListCreateAPIView, MessageListCreateAPIView, ContactSearchAPIView

urlpatterns = [
    path("rooms/", ChatRoomListCreateAPIView.as_view(), name="chat_rooms"),
    path("rooms/<uuid:room_id>/messages/", MessageListCreateAPIView.as_view(), name="chat_messages"),
    path("search/", ContactSearchAPIView.as_view(), name="contact_search"),
]