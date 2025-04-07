from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from .models import ChatRoom, Message
from .serializers import ChatRoomSerializer, MessageSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatRoomViewSet(viewsets.ModelViewSet):
    serializer_class = ChatRoomSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ChatRoom.objects.filter(users=self.request.user)

    def list(self, request, *args, **kwargs):
        target_user_id = request.query_params.get('target_user_id')
        if target_user_id:
            try:
                target_user = User.objects.get(id=target_user_id)
                chat_room = ChatRoom.objects.filter(
                    users=self.request.user
                ).filter(users=target_user).first()
                if chat_room:
                    serializer = self.get_serializer(chat_room)
                    return Response([serializer.data])
                return Response([])
            except User.DoesNotExist:
                return Response([])
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        target_user_id = request.data.get('target_user_id')
        if not target_user_id:
            return Response({'error': 'target_user_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            target_user = User.objects.get(id=target_user_id)
            chat_room = ChatRoom.objects.filter(
                users=self.request.user
            ).filter(users=target_user).first()
            
            if not chat_room:
                chat_room = ChatRoom.objects.create()
                chat_room.users.add(request.user, target_user)
            
            serializer = self.get_serializer(chat_room)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class ChatMessagesView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, room_id):
        try:
            chat_room = ChatRoom.objects.get(id=room_id, users=request.user)
            messages = Message.objects.filter(chat_room=chat_room).order_by('timestamp')
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data)
        except ChatRoom.DoesNotExist:
            return Response({'error': 'Chat room not found'}, status=status.HTTP_404_NOT_FOUND)

class ChatSearchView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        if not query:
            return Response([])
        
        users = User.objects.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        ).exclude(id=request.user.id)
        
        results = [{'id': str(user.id), 'username': user.username} for user in users]
        return Response(results)