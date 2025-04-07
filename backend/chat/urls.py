from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'rooms', views.ChatRoomViewSet, basename='chat-rooms')

urlpatterns = [
    path('', include(router.urls)),
    path('search/', views.ChatSearchView.as_view(), name='chat-search'),
    path('rooms/<uuid:room_id>/messages/', views.ChatMessagesView.as_view(), name='chat-messages'),
]