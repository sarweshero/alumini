from django.shortcuts import render
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .models import ChatRoom, ChatMessage
from .serializers import ChatRoomSerializer, ChatMessageSerializer
from django.contrib.auth import get_user_model
from django.db.models import Q

User = get_user_model()

# List all chat rooms where the current user is a participant
class ChatRoomListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatRoomSerializer

    def get_queryset(self):
        return ChatRoom.objects.filter(participants=self.request.user)


# Create a new chat room
class ChatRoomCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatRoomSerializer

    def perform_create(self, serializer):
        room = serializer.save()
        # Add the creator as a participant by default
        room.participants.add(self.request.user)
        room.save()


# List messages for a specific room
class ChatMessageListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatMessageSerializer

    def get_queryset(self):
        room_id = self.kwargs.get("room_id")
        room = get_object_or_404(ChatRoom, id=room_id)
        if self.request.user in room.participants.all():
            return room.messages.all().order_by('timestamp')
        return ChatMessage.objects.none()


# Create a new message
class ChatMessageCreateView(generics.CreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChatMessageSerializer

    def perform_create(self, serializer):
        room_id = self.kwargs.get("room_id")
        room = get_object_or_404(ChatRoom, id=room_id)
        if self.request.user not in room.participants.all():
            room.participants.add(self.request.user)
        serializer.save(room=room, sender=self.request.user)

# New view to search users by username, first name, or last name (excluding self)
class ChatUserSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        query = request.query_params.get("q", "")
        User = get_user_model()
        if query:
            users = User.objects.filter(
                Q(username__icontains=query) |
                Q(first_name__icontains=query) |
                Q(last_name__icontains=query)
            ).exclude(id=request.user.id)
            data = [{
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name
            } for user in users]
        else:
            data = []
        return Response(data, status=status.HTTP_200_OK)

# New view to start or fetch an existing chat room between current user and target user.
class ChatStartView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        target_user_id = request.data.get("target_user_id")
        if not target_user_id:
            return Response({"error": "target_user_id is required."},
                            status=status.HTTP_400_BAD_REQUEST)
        User = get_user_model()
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        # Look for an existing room containing both users.
        room = ChatRoom.objects.filter(participants=request.user).filter(participants=target_user).first()
        if not room:
            room = ChatRoom.objects.create(
                name=f"Chat between {request.user.username} and {target_user.username}"
            )
            room.participants.add(request.user, target_user)
            room.save()
        serializer = ChatRoomSerializer(room)
        return Response(serializer.data, status=status.HTTP_200_OK)
