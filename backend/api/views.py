from django.contrib.auth import get_user_model, authenticate
from django.http import Http404
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework import status, permissions, generics
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils import timezone
from django.shortcuts import render
from datetime import timedelta
import random
from rest_framework.authtoken.models import Token
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from .models import (
    Events, EventImage, LoginLog, SignupOTP, PendingSignup, Jobs, JobImage, JobComment,
    JobReaction, Album, AlbumImage, user_location
)
from .serializers import (
    EventSerializer, LoginLogSerializer, PendingSignupSerializer, UserSerializer,
    JobsSerializer, JobImageSerializer, JobCommentSerializer, AlbumSerializer,
    AlbumImageSerializer, UserLocationSerializer
)

User = get_user_model()

# ----- Authentication & Login Endpoints -----

class UserLoginHistoryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        logs = LoginLog.objects.filter(user=request.user).order_by('-timestamp')
        serializer = LoginLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user and user.is_superuser:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(
                user=user
            )
            return Response({"token": token.key, "user": user.username, "role": user.role}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials or not admin"}, status=status.HTTP_400_BAD_REQUEST)


class StaffLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user and user.is_staff:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(
                user=user
                )
            return Response({"token": token.key, "user": user.username, "role": user.role}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials or not staff"}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            LoginLog.objects.create(
                user=user
            )
            return Response({"token": token.key, "user": user.username, "role": user.role}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        return Response({'status': 'logged out'}, status=status.HTTP_200_OK)


# ----- Signup & Approval Endpoints -----

class SignupOTPView(APIView):
    def post(self, request, format=None):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required"}, status=status.HTTP_400_BAD_REQUEST)
        code = str(random.randint(100000, 999999))
        SignupOTP.objects.create(email=email, code=code)
        send_mail(
            'Your Signup OTP',
            f'Your OTP for signup is {code}. OTP is valid for 5 minutes.',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        return Response({"message": "OTP sent to email."}, status=status.HTTP_200_OK)


class SignupView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        required_fields = ["name", "college_name", "role", "phone", "username", "password"]
        missing = [field for field in required_fields if not request.data.get(field)]
        
        if not email or not otp or missing:
            error_msg = "Email and OTP required." if not email or not otp else f"Missing fields: {', '.join(missing)}"
            return Response({"error": error_msg}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=request.data.get("username")).exists() or \
           PendingSignup.objects.filter(username=request.data.get("username")).exists():
            return Response({"error": "Username already taken."}, status=status.HTTP_400_BAD_REQUEST)

        otp_entry = SignupOTP.objects.filter(email=email, code=otp).order_by('-created_at').first()
        if not otp_entry or (timezone.now() - otp_entry.created_at > timedelta(minutes=5)):
            if otp_entry:
                otp_entry.delete()
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)
        
        pending, created = PendingSignup.objects.update_or_create(
            email=email,
            defaults={
                'name': request.data.get("name"),
                'college_name': request.data.get("college_name"),
                'role': request.data.get("role"),
                'phone': request.data.get("phone"),
                'username': request.data.get("username"),
                'password': request.data.get("password"),
            }
        )
        send_mail(
            'New Signup Approval Needed',
            f'New signup details:\nEmail: {email}\nName: {request.data.get("name")}\nCollege: {request.data.get("college_name")}\nRole: {request.data.get("role")}\nPhone: {request.data.get("phone")}',
            settings.EMAIL_HOST_USER,
            ['sarweshwardeivasihamani@gmail.com'],
            fail_silently=False,
        )
        otp_entry.delete()
        return Response({"message": "Signup request submitted. Await admin approval."}, status=status.HTTP_200_OK)


class ApproveSignupView(APIView):
    # permission_classes = [permissions.IsAdminUser]
    def get(self, request):
        pending = PendingSignup.objects.filter(is_approved=False)
        serializer = PendingSignupSerializer(pending, many=True)
        return Response(serializer.data)
    
    def post(self, request, format=None):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            pending = PendingSignup.objects.get(email=email, is_approved=False)
        except PendingSignup.DoesNotExist:
            return Response({"error": "Pending signup not found"}, status=status.HTTP_404_NOT_FOUND)
        
        pending.is_approved = True
        pending.approved_at = timezone.now()
        pending.save()

        user = User.objects.create_user(
            username=pending.username,
            email=pending.email,
            password=pending.password
        )
        user.first_name = pending.name
        user.college_name = pending.college_name
        user.role = pending.role
        user.phone = pending.phone
        user.save()
        
        send_mail(
            'Your Account Has Been Approved',
            f'Your account has been approved.\nUsername: {pending.username}',
            settings.EMAIL_HOST_USER,
            [pending.email],
            fail_silently=False,
        )
        pending.delete()
        return Response({"message": "User approved"}, status=status.HTTP_200_OK)
    
    def delete(self, request, format=None):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required to deny signup"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            pending = PendingSignup.objects.get(email=email, is_approved=False)
        except PendingSignup.DoesNotExist:
            return Response({"error": "Pending signup not found"}, status=status.HTTP_404_NOT_FOUND)
        send_mail(
            'Signup Request Denied',
            'Your signup request has been denied by the administrator.',
            settings.EMAIL_HOST_USER,
            [pending.email],
            fail_silently=False,
        )
        pending.delete()
        return Response({"message": "Pending signup request deleted"}, status=status.HTTP_200_OK)


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


class ForgotPasswordView(APIView):
    """
    Accepts an email, generates a password reset token and UID,
    then sends an email with these reset details (or returns them in response).
    """
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{request.scheme}://{request.get_host()}/reset-password/?uid={uid}&token={token}"
        
        # Send email with reset link:
        send_mail(
            'Password Reset Request',
            f'Click the link below to reset your password:\n{reset_link}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        return Response({"message": "Password reset link has been sent to your email."},
                        status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    """
    Template-based view to reset the password.
    GET: Render reset password form with a green and white theme.
    POST: Process the form submission and reset the user's password.
    """
    def get(self, request):
        uid = request.GET.get("uid", "")
        token = request.GET.get("token", "")
        return render(request, "reset_password.html", {"uid": uid, "token": token})
    
    def post(self, request):
        uid = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        
        if not uid or not token or not new_password:
            return Response({"error": "uid, token, and new_password are required."},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            uid_int = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid_int)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            return Response({"error": "Invalid UID."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not default_token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

# ----- Profile Endpoints -----

class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def put(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ----- Event Endpoints -----
class EventDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
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
        if event.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = EventSerializer(event, data=request.data, partial=True)
            if serializer.is_valid():
                event = serializer.save()
                # Update images if provided:
                if request.FILES.getlist('images'):
                    # Optionally, delete old images:
                    event.eventimage_set.all().delete()
                    images = request.FILES.getlist('images')
                    for img in images:
                        EventImage.objects.create(event=event, image=img)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, pk):
        event = self.get_object(pk)
        if event.user == request.user or request.user.role in ["Staff", "Admin"]:
            event.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
    
class EventView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get(self, request):
        events = Events.objects.all().order_by('-uploaded_on')
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def post(self, request, *args, **kwargs):
        data = request.data.dict()
        # Remove 'images' from data to avoid type conflict in serializer validation
        data.pop('images', None)
        data['uploaded_by'] = request.user.role
        data['user'] = request.user.id 
        images = request.FILES.getlist('images')
        serializer = EventSerializer(data=data)
        if serializer.is_valid():
            event = serializer.save(user=request.user)
            for img in images:
                EventImage.objects.create(event=event, image=img)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ----- Job Endpoints -----

class JobListCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get(self, request):
        jobs = Jobs.objects.all().order_by('-posted_on')
        serializer = JobsSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def post(self, request):
        job_data = request.data.dict()  # Avoid deep-copying file objects.
        images = request.FILES.getlist('images')
        job_data['uploaded_by'] = request.user.role
        serializer = JobsSerializer(data=job_data)
        if serializer.is_valid():
            job = serializer.save(user=request.user, role=request.user.role)
            for image in images:
                JobImage.objects.create(job=job, image=image)
            updated_serializer = JobsSerializer(job)
            return Response(updated_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get_object(self, pk):
        try:
            return Jobs.objects.get(pk=pk)
        except Jobs.DoesNotExist:
            raise Http404
    def get(self, request, pk):
        job = self.get_object(pk)
        from django.core.cache import cache
        cache_key = f"job_view_{request.user.id}_{job.id}"
        if not cache.get(cache_key):
            job.views += 1
            job.save(update_fields=["views"])
            cache.set(cache_key, True, 3600)
        serializer = JobsSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def put(self, request, pk):
        job = self.get_object(pk)
        if job.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = JobsSerializer(job, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, pk):
        job = self.get_object(pk)
        if job.user == request.user or request.user.role in ["Staff", "Admin"]:
            job.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)


class JobImagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, job_id):
        images = JobImage.objects.filter(job=job_id)
        serializer = JobImageSerializer(images, many=True)
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
        if comment.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = JobCommentSerializer(comment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
    def delete(self, request, pk):
        comment = self.get_object(pk)
        if comment.user == request.user or request.user.role in ["Staff", "Admin"]:
            comment.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)


# ----- Home & Reaction Endpoints -----

class HomePageDataView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        latest_events = Events.objects.all().order_by('-uploaded_on')[:5]
        events_serializer = EventSerializer(latest_events, many=True)
        latest_jobs = Jobs.objects.all().order_by('-posted_on')[:5]
        jobs_serializer = JobsSerializer(latest_jobs, many=True)
        latest_album_images = Album.objects.all().order_by('-id')[:10]
        album_images_serializer = AlbumSerializer(latest_album_images, many=True)
        latest_members = User.objects.filter(role='Student').order_by('-id')[:60]
        members_serializer = UserSerializer(latest_members, many=True)
        return Response({
            'latest_events': events_serializer.data,
            'latest_jobs': jobs_serializer.data,
            'latest_album_images': album_images_serializer.data,
            'latest_members': members_serializer.data,
        }, status=status.HTTP_200_OK)



class JobReactionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, job_id):
        reaction_data = request.data.get("reaction")

        if not isinstance(reaction_data, dict):
            return Response({"error": "Invalid reaction format."}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the first reaction type (e.g., {"like": 1})
        reaction_type = next(iter(reaction_data), None)
        reaction_value = reaction_data.get(reaction_type)

        if reaction_type not in {"like"}:
            return Response({"error": "Invalid or missing reaction type."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            job = Jobs.objects.get(id=job_id)
        except Jobs.DoesNotExist:
            return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

        # Get or initialize reaction count
        current_counts = job.reaction or {}
        current_counts.setdefault(reaction_type, 0)

        try:
            user_reaction = JobReaction.objects.get(job=job, user=request.user)

            if reaction_value == 1:
                if user_reaction.reaction != reaction_type:
                    # Changing reaction type (future multi-reaction support)
                    previous = user_reaction.reaction
                    current_counts[previous] = max(current_counts.get(previous, 1) - 1, 0)
                    current_counts[reaction_type] = current_counts.get(reaction_type, 0) + 1
                    user_reaction.reaction = reaction_type
                    user_reaction.save()
                # If same reaction, do nothing
            else:
                # reaction_value == 0 → User is unliking
                previous = user_reaction.reaction
                current_counts[previous] = max(current_counts.get(previous, 1) - 1, 0)
                user_reaction.delete()

        except JobReaction.DoesNotExist:
            if reaction_value == 1:
                # First time like
                current_counts[reaction_type] = current_counts.get(reaction_type, 0) + 1
                JobReaction.objects.create(job=job, user=request.user, reaction=reaction_type)

        # Save new state
        job.reaction = current_counts
        job.save(update_fields=["reaction"])

        return Response({
            "reaction": job.reaction,
            "like_count": current_counts.get("like", 0),
            "message": "Reaction updated successfully"
        }, status=status.HTTP_200_OK)
    # ----- Album Endpoints -----

class AlbumImagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get_object(self, pk):
        try:
            return AlbumImage.objects.get(pk=pk)
        except AlbumImage.DoesNotExist:
            raise Http404
    def get(self, request, album_id):
        images = AlbumImage.objects.filter(album__id=album_id)
        serializer = AlbumImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def post(self, request, album_id):
        try:
            album = Album.objects.get(id=album_id)
        except Album.DoesNotExist:
            return Response({"error": "Album not found"}, status=status.HTTP_404_NOT_FOUND)
        images = request.FILES.getlist('images')
        if not images:
            return Response({"error": "No Image provided"}, status=status.HTTP_204_NO_CONTENT)
        created_images = []
        for image in images:
            serializer = AlbumImageSerializer(data={'image': image, 'album': album.id})
            if serializer.is_valid():
                serializer.save(album=album)
                created_images.append(serializer.data)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(created_images, status=status.HTTP_201_CREATED)
    def put(self, request, album_id):
        album_image = self.get_object(album_id)
        if album_image.album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        serializer = AlbumImageSerializer(album_image, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, album_id):
        album_image = self.get_object(album_id)
        if album_image.album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        album_image.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AlbumDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    def get(self, request):
        albums = Album.objects.all().order_by("-id")
        serializer = AlbumSerializer(albums, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    def get_object(self, pk):
        try:
            return Album.objects.get(pk=pk)
        except Album.DoesNotExist:
            raise Http404
    def post(self, request):
        album_data = request.data.dict()
        images = request.FILES.getlist('images')
        serializer = AlbumSerializer(data=album_data)
        serializer.is_valid(raise_exception=True)
        album = serializer.save(user=request.user)
        created_images = []
        for image in images:
            img_serializer = AlbumImageSerializer(data={'image': image, 'album': album.id})
            if img_serializer.is_valid():
                img_serializer.save(album=album)
                created_images.append(img_serializer.data)
            else:
                return Response(img_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        response_data = serializer.data
        response_data['images'] = created_images
        return Response(response_data, status=status.HTTP_201_CREATED)
    def put(self, request, pk):
        album = self.get_object(pk)
        if album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        serializer = AlbumSerializer(album, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    def delete(self, request, pk):
        album = self.get_object(pk)
        if album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        album.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class MyPostsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        jobs = Jobs.objects.filter(user=request.user).order_by('-posted_on')
        serializer = JobsSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ----- User Location Endpoints -----

class UserLocationListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        return user_location.objects.all()
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class UserLocationRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    def get_queryset(self):
        return user_location.objects.filter(user=self.request.user)