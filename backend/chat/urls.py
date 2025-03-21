from django.urls import path
from .views import ChatRoomAPIView, UserSearchAPIView, AvailableChatsAPIView

urlpatterns = [
    path('rooms/<str:room_name>/messages/', ChatRoomAPIView.as_view(), name='chat_room_api'),
    path('search/', UserSearchAPIView.as_view(), name='user_search'),
    path('rooms/', AvailableChatsAPIView.as_view(), name='available_chats'),
]