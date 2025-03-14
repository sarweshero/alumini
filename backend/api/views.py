from django.contrib.auth import authenticate, get_user_model
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, serializers
from rest_framework.authtoken.models import Token
from rest_framework.parsers import MultiPartParser, FormParser
from .models import *
from .serializers import *
from user_agents import parse
from django.utils import timezone
from django.core.cache import cache
User = get_user_model()

def get_user_agent_info(request):
    """Extract browser, OS, and device details from request headers."""
    user_agent = parse(request.META.get("HTTP_USER_AGENT", ""))
    return {
        "browser": user_agent.browser.family,
        "browser_version": user_agent.browser.version_string,
        "device": user_agent.device.brand or "Unknown",
    }

class UserLoginHistoryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Returns all login logs for the authenticated user."""
        logs = LoginLog.objects.filter(user=request.user).order_by('-timestamp')
        serializer = LoginLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
class AdminLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        ip_address = request.META.get("REMOTE_ADDR")
        user_agent_info = get_user_agent_info(request)

        user = authenticate(username=username, password=password)
        if user and user.is_superuser:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=True, **user_agent_info
            )
            return Response({"token": token.key, "user": user.username}, status=status.HTTP_200_OK)

        if user:
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=False, **user_agent_info
            )
        return Response(
            {"error": "Invalid credentials or not admin"}, status=status.HTTP_400_BAD_REQUEST
        )


class StaffLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        ip_address = request.META.get("REMOTE_ADDR")
        user_agent_info = get_user_agent_info(request)

        user = authenticate(username=username, password=password)
        if user and user.is_staff and not user.is_superuser:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=True, **user_agent_info
            )
            return Response({"token": token.key, "user": user.username}, status=status.HTTP_200_OK)

        if user:
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=False, **user_agent_info
            )
        return Response(
            {"error": "Invalid credentials or not staff"}, status=status.HTTP_400_BAD_REQUEST
        )


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        ip_address = request.META.get("REMOTE_ADDR")
        user_agent_info = get_user_agent_info(request)

        user = authenticate(username=username, password=password)
        if user and not user.is_staff and not user.is_superuser:
            token, _ = Token.objects.get_or_create(user=user)
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=True, **user_agent_info
            )
            return Response({"token": token.key, "user": user.username}, status=status.HTTP_200_OK)

        if user:
            LoginLog.objects.create(
                user=user, ip_address=ip_address, successful=False, **user_agent_info
            )
        return Response(
            {"error": "Invalid credentials or not a regular user"},
            status=status.HTTP_400_BAD_REQUEST,
        )


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        return Response({'status': 'logged out'}, status=status.HTTP_200_OK)

class UserSignupView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if User.objects.filter(username=username).exists():
            return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        return Response({'status': 'User created'}, status=status.HTTP_201_CREATED)

        
class SignupView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        # Only admin (superuser) can create new users
        if not request.user.is_superuser | request.user.is_staff:
            return Response({'error': 'Only admin can add users'}, status=status.HTTP_403_FORBIDDEN)
        username = request.data.get('username')
        password = request.data.get('password')
        account_type = request.data.get('account_type', 'user')  # default to "user"
        if User.objects.filter(username=username).exists():
            return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.create_user(username=username, password=password)
        if account_type == 'admin':
            user.is_superuser = True
            user.is_staff = True
        elif account_type == 'staff':
            user.is_staff = True
        user.save()
        return Response({'status': 'User created'}, status=status.HTTP_201_CREATED)


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        if not request.user.check_password(old_password):
            return Response({'error': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save()
        return Response({'status': 'Password changed successfully'}, status=status.HTTP_200_OK)




# API endpoint to view or update basic profile details
class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        profile_serializer = ProfileSerializer(profile)
        user_serializer = UserSerializer(request.user)
        return Response(profile_serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            profile_serializer = ProfileSerializer(profile)
            return Response(profile_serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def patch(self, request):
    #     return self.put(request)

class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
            profile, created = Profile.objects.get_or_create(user=user)
            profile_serializer = ProfileSerializer(profile)
            user_serializer = UserSerializer(user)
            return Response(profile_serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class EventDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Change to IsAdminUser if necessary
    parser_classes = (MultiPartParser, FormParser)

    def get_object(self, pk):
        try:
            return Events.objects.get(pk=pk)
        except Events.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        event = self.get_object(pk)
        serializer = EventSerializer(event)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        event = self.get_object(pk)
        serializer = EventSerializer(event, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        event = self.get_object(pk)
        event.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class EventView(APIView):
    permission_classes = [permissions.IsAuthenticated]  # Change to IsAdminUser if necessary
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        events = Events.objects.all().order_by('-uploaded_on')
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = EventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class JobListCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        jobs = Jobs.objects.all().order_by('-posted_on')
        serializer = JobsSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        # Handle job data
        job_data = request.data.copy()
        images = request.FILES.getlist('images')  # Get list of uploaded images
        
        serializer = JobsSerializer(data=job_data)
        if serializer.is_valid():
            job = serializer.save(user=request.user)
            
            # Handle image uploads
            for image in images:
                JobImage.objects.create(job=job, image=image)
            
            # Re-serialize with images included
            updated_serializer = JobsSerializer(job)
            return Response(updated_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobDetailView(APIView):
    """
    Retrieve, update, or delete a job posting.
    Also increments the job's view count upon a GET request.
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get_object(self, pk):
        try:
            return Jobs.objects.get(pk=pk)
        except Jobs.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        job = self.get_object(pk)
        user = request.user
        cache_key = f"job_view_{user.id}_{job.id}"
        # Only increment if the user hasn't viewed this job in the last hour.
        if not cache.get(cache_key):
            job.views += 1
            job.save(update_fields=["views"])
            cache.set(cache_key, True, 3600)  # Cache expires in one hour.
        serializer = JobsSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        job = self.get_object(pk)
        serializer = JobsSerializer(job, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()  # Add additional permission checks if required
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        job = self.get_object(pk)
        job.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class JobImagesView(APIView):
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, job_id):
        image = JobImage.objects.filter(job=job_id)
        serializer = JobImageSerializer(image, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, job_id):
        try:
            job = Jobs.objects.get(id=job_id)
        except Jobs.DoesNotExist:
            return Response({"detail": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = JobImageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(job=job)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobCommentListCreateView(APIView):
    """
    List all comments for a job or create a new comment.
    The job id is passed as a URL parameter.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, job_id):
        comments = JobComment.objects.filter(job__id=job_id).order_by('-created_at')
        serializer = JobCommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, job_id):
        try:
            job = Jobs.objects.get(id=job_id)
        except Jobs.DoesNotExist:
            return Response({"detail": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = JobCommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(job=job, user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobCommentDetailView(APIView):

    """
    Retrieve, update, or delete a specific job comment.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, pk):
        try:
            return JobComment.objects.get(pk=pk)
        except JobComment.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        comment = self.get_object(pk)
        serializer = JobCommentSerializer(comment)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        comment = self.get_object(pk)
        if comment.user == request.user:
            serializer = JobCommentSerializer(comment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # Optionally enforce that only the comment owner can update
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        if comment.user == request.user:
            comment = self.get_object(pk)
            comment.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)


class HomePageDataView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Fetch latest events
        latest_events = Events.objects.all().order_by('-uploaded_on')[:5]
        events_serializer = EventSerializer(latest_events, many=True)

        # Fetch latest jobs
        latest_jobs = Jobs.objects.all().order_by('-posted_on')[:5]
        jobs_serializer = JobsSerializer(latest_jobs, many=True)

        # Fetch latest album images
        latest_album_images = Album.objects.all().order_by('-id')[:10]
        album_images_serializer = AlbumSerializer(latest_album_images, many=True)

        # Fetch latest members
        latest_members = Profile.objects.all().order_by('-id')[:60]
        members_serializer = memberSerializer(latest_members, many=True)

        return Response({
            'latest_events': events_serializer.data,
            'latest_jobs': jobs_serializer.data,
            'latest_album_images': album_images_serializer.data,
            'latest_members': members_serializer.data,
        }, status=status.HTTP_200_OK)

class JobReactionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, job_id):
        reaction_type = request.data.get("reaction")
        allowed_reactions = {"like", "love", "haha", "wow", "sad"}
        if reaction_type not in allowed_reactions:
            return Response({"error": "Invalid reaction type."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            job = Jobs.objects.get(id=job_id)
        except Jobs.DoesNotExist:
            return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        
        current_counts = job.reaction or {}

        try:
            user_reaction = JobReaction.objects.get(job=job, user=request.user)
            previous = user_reaction.reaction
            if previous == reaction_type:
                # Remove reaction if same button pressed again.
                current_counts[previous] = max(current_counts.get(previous, 0) - 1, 0)
                user_reaction.delete()
            else:
                # Change reaction: decrement previous and increment new.
                current_counts[previous] = max(current_counts.get(previous, 0) - 1, 0)
                current_counts[reaction_type] = current_counts.get(reaction_type, 0) + 1
                user_reaction.reaction = reaction_type
                user_reaction.save()
        except JobReaction.DoesNotExist:
            # New reaction.
            current_counts[reaction_type] = current_counts.get(reaction_type, 0) + 1
            JobReaction.objects.create(job=job, user=request.user, reaction=reaction_type)

        job.reaction = current_counts
        job.save(update_fields=["reaction"])
        return Response({"reaction": job.reaction}, status=status.HTTP_200_OK)

class AlbumImagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, album_id):
        try:
            album = models.Album.objects.get(id=album_id)
        except models.Album.DoesNotExist:
            return Response({"error": "Album not found."}, status=status.HTTP_404_NOT_FOUND)
        
        images = album.images.all()  # using related_name 'images'
        serializer = AlbumImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MyPostsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        jobs = Jobs.objects.filter(user=request.user).order_by('-posted_on')
        serializer = JobsSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)