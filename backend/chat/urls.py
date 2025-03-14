from django.urls import path
from .views import (
    ChatRoomListView,
    ChatRoomCreateView,
    ChatMessageListView,
    ChatMessageCreateView,
    ChatUserSearchView,       # new
    ChatStartView             # new
)

urlpatterns = [
    path('rooms/', ChatRoomListView.as_view(), name='chat-room-list'),
    path('rooms/create/', ChatRoomCreateView.as_view(), name='chat-room-create'),
    path('rooms/search/', ChatUserSearchView.as_view(), name='chat-user-search'),  # new endpoint
    path('rooms/start/', ChatStartView.as_view(), name='chat-start'),              # new endpoint
    path('rooms/<int:room_id>/messages/', ChatMessageListView.as_view(), name='chat-message-list'),
    path('rooms/<int:room_id>/messages/create/', ChatMessageCreateView.as_view(), name='chat-message-create'),
]
