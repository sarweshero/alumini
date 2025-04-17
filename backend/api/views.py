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
import csv
import os
from django.db import models

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
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Try to get user by email if identifier contains '@'
        if identifier and ("@" in identifier or "." in identifier):
            try:
                user_obj = User.objects.get(email=identifier)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        else:
            user = authenticate(username=identifier, password=password)

        if user and user.is_superuser:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(user=user)
            return Response({"token": token.key, "user": user.username, "role": user.role}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials or not admin"}, status=status.HTTP_400_BAD_REQUEST)


class StaffLoginView(APIView):
    def post(self, request):
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Allow login by email or username
        if identifier and ("@" in identifier or "." in identifier):
            try:
                user_obj = User.objects.get(email=identifier)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        else:
            user = authenticate(username=identifier, password=password)

        if user and user.is_staff:
            token, _ = Token.objects.get_or_create(user=user)
            LoginLog.objects.create(user=user)
            return Response({"token": token.key, "user": user.username, "role": user.role}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials or not staff"}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Allow login by email or username
        if identifier and ("@" in identifier or "." in identifier):
            try:
                user_obj = User.objects.get(email=identifier)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        else:
            user = authenticate(username=identifier, password=password)

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
        username = request.data.get("username", email)
        user_fields = [f.first_name for f in PendingSignup._meta.fields if f.name not in ("id", "created_at", "is_approved", "approved_at", "username", "password", "email")]
        required_fields = ["first_name", "college_name", "role", "phone", "password"]
        missing = [field for field in required_fields if not request.data.get(field)]

        if not email or not otp or missing:
            error_msg = "Email and OTP required." if not email or not otp else f"Missing fields: {', '.join(missing)}"
            return Response({"error": error_msg}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists() or PendingSignup.objects.filter(email=email).exists():
            return Response({"error": "Email already taken."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists() or PendingSignup.objects.filter(username=username).exists():
            return Response({"error": "Username already taken."}, status=status.HTTP_400_BAD_REQUEST)

        otp_entry = SignupOTP.objects.filter(email=email, code=otp).order_by('-created_at').first()
        if not otp_entry or (timezone.now() - otp_entry.created_at > timedelta(minutes=30)):
            if otp_entry:
                otp_entry.delete()
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        pending_data = {field: request.data.get(field, "") for field in user_fields}
        pending_data['email'] = email
        pending_data['username'] = username
        pending_data['password'] = request.data.get("password")

        # Convert all DateField empty strings to None
        for field in PendingSignup._meta.fields:
            if isinstance(field, (models.DateField, models.DateTimeField)):
                if pending_data.get(field.name) == "":
                    pending_data[field.name] = None

        PendingSignup.objects.update_or_create(
            email=email,
            defaults=pending_data
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

        user_data = {}
        # Iterate over all user fields except these fields
        for field in [f for f in User._meta.fields if f.name not in ("id", "last_login", "date_joined", "password")]:
            value = getattr(pending, field.name, "")
            if value is None:
                value = ""
            # For date fields, convert empty string to None
            if isinstance(field, (models.DateField, models.DateTimeField)):
                if value == "":
                    value = None
            user_data[field.name] = value

        # Preserve the provided username instead of forcing email as username
        user_data['username'] = pending.username  
        user_data['email'] = pending.email

        # Set required boolean fields
        user_data['is_superuser'] = False
        user_data['is_active'] = True
        user_data['is_staff'] = (pending.role.lower() == "staff")

        # Use custom manager if available; otherwise, create the user normally
        user = User.objects.create_user(**user_data)  # or use .create(**user_data)
        user.set_password(pending.password)
        user.save()

        pending.is_approved = True
        pending.approved_at = timezone.now()
        pending.save()
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
        jobs_serializer = JobsSerializer(jobs, many=True)
        events = Events.objects.filter(user=request.user).order_by('-uploaded_on')
        events_serializer = EventSerializer(events, many=True)
        return Response({
            "jobs": jobs_serializer.data,
            "events": events_serializer.data
        }, status=status.HTTP_200_OK)

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
    
class UserLocationsearchAPIView(generics.ListAPIView):
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        name = self.request.query_params.get("name", "")
        if name:
            from django.db.models import Q
            return user_location.objects.filter(
                Q(user__first_name__icontains=name) |
                Q(user__last_name__icontains=name) |
                Q(user__username__icontains=name)
            )
        return user_location.objects.none()

    def list(self, _request, *_args, **_kwargs):
        queryset = self.get_queryset()
        results = list(queryset.values())
        return Response(results, status=status.HTTP_200_OK)

class ImportMembersAPIView(APIView):
    """
    POST: Import registered members from members.csv into the CustomUser model.
    Email is used as username. Date of Birth is set as password (in 'YYYY-MM-DD' format).
    All available fields from the CSV are mapped to the CustomUser model.
    If the row is a faculty, set role='Staff' and is_staff=True.
    """
    def post(self, request):
        User = get_user_model()
        csv_path = os.path.join(settings.BASE_DIR, 'members.csv')
        created, updated, skipped = [], [], []
        with open(csv_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                email = row.get('email_id', '').strip().lower()
                if not email:
                    skipped.append("No email in row")
                    continue
                username = email
                dob = row.get('Date of Birth', '').strip()
                password = dob if dob else 'defaultpassword'
                # Prepare user data mapping
                user_data = {
                    "username": username,
                    "email": email,
                    "salutation": row.get('Salutation', '').strip(),
                    "first_name": row.get('Name', '').strip(),
                    "gender": row.get('Gender', '').strip(),
                    "date_of_birth": row.get('Date of Birth', '').strip() or None,
                    "label": row.get('Label', '').strip(),
                    "secondary_email": row.get('Secondary Email', '').strip(),
                    "registered": row.get('Registered', '').strip(),
                    "registered_on": row.get('Registered On', '').strip(),
                    "approved_on": row.get('Approved On', '').strip(),
                    "profile_updated_on": row.get('Profile Updated On', '').strip(),
                    "profile_type": row.get('Profile Type', '').strip(),
                    "roll_no": row.get('Roll No', '').strip(),
                    "institution_name": row.get('Institution Name', '').strip(),
                    "course": row.get('Course', '').strip(),
                    "stream": row.get('Stream', '').strip(),
                    "course_start_year": row.get('Course Start Year', '').strip(),
                    "course_end_year": row.get('Course End Year', '').strip(),
                    "employee_id": row.get('Employee ID', '').strip(),
                    "faculty_job_title": row.get('Faculty: Job Title', '').strip(),
                    "faculty_institute": row.get('Faculty: Institute', '').strip(),
                    "faculty_department": row.get('Faculty: Department', '').strip(),
                    "faculty_start_year": row.get('Faculty: Start Year', '').strip(),
                    "faculty_start_month": row.get('Faculty: Start Month', '').strip(),
                    "faculty_end_year": row.get('Faculty: End Year', '').strip(),
                    "faculty_end_month": row.get('Faculty: End Month', '').strip(),
                    "mobile_phone_no": row.get('Mobile Phone No.', '').strip(),
                    "home_phone_no": row.get('Home Phone No.', '').strip(),
                    "office_phone_no": row.get('Office Phone No.', '').strip(),
                    "current_location": row.get('Current Location', '').strip(),
                    "home_town": row.get('Home Town', '').strip(),
                    "correspondence_address": row.get('Correspondence Address', '').strip(),
                    "correspondence_city": row.get('Correspondence City', '').strip(),
                    "correspondence_state": row.get('Correspondence State', '').strip(),
                    "correspondence_country": row.get('Correspondence Country', '').strip(),
                    "correspondence_pincode": row.get('Correspondence Pincode', '').strip(),
                    "company": row.get('Company', '').strip(),
                    "position": row.get('Position', '').strip(),
                    "member_roles": row.get('Member Roles', '').strip(),
                    "educational_course": row.get('Educational Course', '').strip(),
                    "educational_institute": row.get('Educational Institute', '').strip(),
                    "start_year": row.get('Start Year', '').strip(),
                    "end_year": row.get('End Year', '').strip(),
                    "facebook_link": row.get('Facebook Link', '').strip(),
                    "linkedin_link": row.get('LinkedIn Link', '').strip(),
                    "website_link": row.get('Website Link', '').strip(),
                    "work_experience": float(row.get('Work Experience(in years)', '0').strip() or 0),
                    "chapter": row.get('chapter', '').strip(),
                }
                # JSON fields
                for field, csv_field in [
                    ('professional_skills', 'Professional Skills'),
                    ('industries_worked_in', 'Industries Worked In'),
                    ('roles_played', 'Roles Played')
                ]:
                    val = row.get(csv_field, '').strip()
                    user_data[field] = [v.strip() for v in val.split(',')] if val else []

                # Social links as JSON
                user_data['social_links'] = {
                    "Facebook": row.get('Facebook Link', '').strip(),
                    "LinkedIn": row.get('LinkedIn Link', '').strip(),
                    "Twitter": row.get('Twitter Link', '').strip(),
                    "Website": row.get('Website Link', '').strip(),
                }

                # Set role and is_staff for faculty
                profile_type = row.get('Profile Type', '').strip().lower()
                label = row.get('Label', '').strip().lower()
                if profile_type == 'faculty' or label == 'faculty':
                    user_data['role'] = 'Staff'
                    user_data['is_staff'] = True

                try:
                    user = User.objects.get(email=email)
                    for k, v in user_data.items():
                        setattr(user, k, v)
                    if password:
                        user.set_password(password)
                    user.save()
                    updated.append(email)
                except User.DoesNotExist:
                    user = User(**user_data)
                    user.set_password(password)
                    user.save()
                    created.append(email)
                except Exception as e:
                    skipped.append(f"{email} ({str(e)})")

        return Response({
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "message": f"{len(created)} users created, {len(updated)} updated, {len(skipped)} skipped."
        }, status=status.HTTP_201_CREATED)