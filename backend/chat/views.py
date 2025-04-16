from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from .models import ChatRoom, Message
from .serializers import ChatRoomSerializer, MessageSerializer, UserSerializer

User = get_user_model()

class ChatRoomListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = ChatRoomSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        target_user_id = self.request.query_params.get("target_user_id")
        qs = ChatRoom.objects.filter(users=user)
        if target_user_id:
            qs = qs.filter(users__id=target_user_id)
        return qs.distinct()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["request"] = self.request
        return context

    # ... rest of your code ...

    def create(self, request, *args, **kwargs):
        target_user_id = request.data.get("target_user_id")
        if not target_user_id:
            return Response(
                {"detail": "target_user_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        # Check if a chat room already exists with the target user.
        user = request.user
        existing_rooms = ChatRoom.objects.filter(users=user).filter(users=target_user)
        if existing_rooms.exists():
            serializer = self.get_serializer(existing_rooms.first(), context={"request": request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        # Otherwise, create a new room.
        room = ChatRoom.objects.create()
        room.users.add(user, target_user)
        serializer = self.get_serializer(room, context={"request": request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class MessageListCreateAPIView(generics.ListCreateAPIView):
    """
    GET: List messages for a specific chat room.
    POST: Create a new message in a specific chat room.
    """
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        room_id = self.kwargs.get("room_id")
        # Try to get the chat room; if not found, return empty queryset instead of 404
        try:
            chat_room = ChatRoom.objects.get(id=room_id, users=self.request.user)
        except ChatRoom.DoesNotExist:
            return Message.objects.none()
        return Message.objects.filter(chat_room=chat_room).order_by("timestamp")

    def perform_create(self, serializer):
        room_id = self.kwargs.get("room_id")
        chat_room = get_object_or_404(ChatRoom, id=room_id, users=self.request.user)
        serializer.save(sender=self.request.user, chat_room=chat_room)

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if queryset is not None and not queryset.exists():
            # Optionally, create a default message if the room exists but has no messages
            pass  # Remove or keep your default message logic as needed
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
class ContactSearchAPIView(generics.ListAPIView):
    """
    GET: Search for users by username (excluding the current user).
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        query = self.request.query_params.get("q", "")
        return User.objects.filter(username__icontains=query).exclude(id=self.request.user.id)