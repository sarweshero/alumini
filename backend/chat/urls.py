from django.urls import path, include
from .views import ChatRoomListView, ChatRoomMessagesView, StartChatView, SearchUsersView

urlpatterns = [
    path("rooms/", ChatRoomListView.as_view(), name="chat-rooms"),
    path("rooms/<uuid:room_id>/messages/", ChatRoomMessagesView.as_view(), name="chat-messages"),
    path("start/", StartChatView.as_view(), name="start-chat"),
    path("search/", SearchUsersView.as_view(), name="search-users"),
]