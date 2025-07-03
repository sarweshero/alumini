"""
Alumni Portal API Views
========================
This module contains all REST API endpoints for the Alumni Portal application.
The views are organized by feature area:
- Authentication & User Management
- Profiles
- Events
- Jobs & Reactions
- Albums & Media
- Business Directory
- News & Articles
- Utilities & Home Page
"""

import os
import csv
import json
import random
import pandas as pd
import django_filters
from django.db import models
from datetime import datetime
from datetime import timedelta
from django.http import Http404
from django.conf import settings
from django.utils import timezone
from django.shortcuts import render
from django.core.cache import cache
from django.db.models import Q, Count
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.encoding import force_bytes
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework import status, permissions, generics
from django.contrib.auth import get_user_model, authenticate
from rest_framework.generics import ListAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import OrderingFilter, SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from .models import (
    # User-related models
    LoginLog, SignupOTP, PendingSignup, user_location,
    # Content models
    Events, EventImage, Jobs, JobImage, JobComment, JobReaction,
    Album, AlbumImage, BusinessDirectory, BusinessImage,
    NewsRoom, NewsImage
)
from .serializers import (
    # User-related serializers
    UserSerializer, LoginLogSerializer, PendingSignupSerializer, UserLocationSerializer,
    # Content serializers
    EventSerializer, JobsSerializer, JobImageSerializer, JobCommentSerializer,
    AlbumSerializer, AlbumImageSerializer, BusinessDirectorySerializer, BusinessImageSerializer,
    NewsRoomSerializer, NewsImageSerializer
)

User = get_user_model()

#####################################
# AUTHENTICATION & USER MANAGEMENT  #
#####################################

class UserLoginHistoryView(APIView):
    """View for retrieving a user's login history."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Return all login history records for the authenticated user."""
        logs = LoginLog.objects.filter(user=request.user).order_by('-timestamp')
        serializer = LoginLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ChangeUsernameView(APIView):
    """View for changing a user's username without password verification."""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Change the username of the authenticated user.
        
        Required payload:
            - new_username: The desired new username
            
        Returns:
            Success or error message with appropriate status code
        """
        new_username = request.data.get('new_username')
        
        # Validate input
        if not new_username:
            return Response(
                {"error": "New username is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if username already exists in Users table
        User = get_user_model()
        if User.objects.filter(username=new_username).exists():
            return Response(
                {"error": "This username is already taken"}, 
                status=status.HTTP_409_CONFLICT
            )
        
        # Check if username already exists in PendingSignup table
        if PendingSignup.objects.filter(username=new_username).exists():
            return Response(
                {"error": "This username is already in the pending approval queue"}, 
                status=status.HTTP_409_CONFLICT
            )
        
        # Validate username format
        import re
        if not re.match(r'^[\w.@+-]+$', new_username):
            return Response(
                {"error": "Username may only contain letters, numbers, and @/./+/-/_ characters"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if len(new_username) > 150:
            return Response(
                {"error": "Username must be 150 characters or fewer"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update username
        old_username = request.user.username
        request.user.username = new_username
        request.user.save(update_fields=['username'])
        
        # Log the change
        from django.utils import timezone
        LoginLog.objects.create(
            user=request.user,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            timestamp=timezone.now()
        )
        
        return Response({
            "success": True,
            "message": "Username successfully updated",
            "old_username": old_username,
            "new_username": new_username
        }, status=status.HTTP_200_OK)
    

class AdminLoginView(APIView):
    """View for admin authentication."""
    
    def post(self, request):
        """
        Authenticate admin users with email or username.
        
        Returns:
            Authentication token if successful
        """
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Support login by email or username
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
            return Response({
                "token": token.key, 
                "user": user.username, 
                "role": user.role
            }, status=status.HTTP_200_OK)
        
        return Response(
            {"error": "Invalid credentials or not admin"}, 
            status=status.HTTP_400_BAD_REQUEST
        )


class StaffLoginView(APIView):
    """View for staff authentication."""
    
    def post(self, request):
        """
        Authenticate staff users with email or username.
        
        Returns:
            Authentication token if successful
        """
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Support login by email or username
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
            return Response({
                "token": token.key, 
                "user": user.username, 
                "role": user.role
            }, status=status.HTTP_200_OK)
        
        return Response(
            {"error": "Invalid credentials or not staff"}, 
            status=status.HTTP_400_BAD_REQUEST
        )


class UserLoginView(APIView):
    """View for regular user authentication."""
    
    def post(self, request):
        """
        Authenticate regular users with email or username.
        
        Returns:
            Authentication token if successful
        """
        identifier = request.data.get("username")
        password = request.data.get("password")
        user = None

        # Support login by email or username
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
            # Update last login time
            user.last_login = timezone.now()
            user.save(update_fields=["last_login"])
            # Log the login
            LoginLog.objects.create(user=user)
            
            return Response({
                "token": token.key, 
                "user": user.username, 
                "role": user.role
            }, status=status.HTTP_200_OK)
        
        return Response(
            {"error": "Invalid credentials"}, 
            status=status.HTTP_400_BAD_REQUEST
        )


class LogoutView(APIView):
    """View for user logout."""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Delete the user's authentication token."""
        request.user.auth_token.delete()
        return Response({'status': 'logged out'}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    """View for initiating password reset."""
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """
        Send a password reset link to the user's email.
        
        Returns:
            Success message if email was sent
        """
        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "Email is required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist."}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Generate reset token and URL
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = request.build_absolute_uri(f"/reset-password/?uid={uid}&token={token}")
        
        # Send email with reset link
        subject = "Reset Your Password"
        message = f"Please click the following link to reset your password:\n{reset_link}"
        send_mail(
            subject, 
            message, 
            settings.EMAIL_HOST_USER, 
            [email], 
            fail_silently=False
        )
        
        return Response(
            {"message": "Password reset link sent to your email."}, 
            status=status.HTTP_200_OK
        )


class ResetPasswordView(APIView):
    """View for completing password reset."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """Render the password reset UI."""
        uid = request.GET.get("uid", "")
        token = request.GET.get("token", "")
        return render(request, "reset_password.html", {"uid": uid, "token": token})
    
    def post(self, request):
        """
        Reset the user's password with the provided token.
        
        Returns:
            Success message if password was reset
        """
        uid = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        
        if not uid or not token or not new_password:
            return Response(
                {"error": "uid, token and new_password are required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            user_id = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response(
                {"error": "Invalid uid."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": "Invalid or expired token."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user.set_password(new_password)
        user.save()
        return Response(
            {"message": "Password reset successful."}, 
            status=status.HTTP_200_OK
        )


class ChangePasswordView(APIView):
    """View for changing password while authenticated."""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Change the user's password.
        
        Returns:
            Success message if password was changed
        """
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        
        if not request.user.check_password(old_password):
            return Response(
                {'error': 'Incorrect old password'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        request.user.set_password(new_password)
        request.user.save()
        return Response(
            {'status': 'Password changed successfully'}, 
            status=status.HTTP_200_OK
        )


class SignupOTPView(APIView):
    """View for sending signup OTP."""
    
    def post(self, request, format=None):
        """
        Send a one-time password to the provided email for signup verification.
        
        Returns:
            Success message if OTP was sent
        """
        email = request.data.get("email")
        if not email:
            return Response(
                {"error": "Email required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Generate 6-digit OTP
        code = str(random.randint(100000, 999999))
        SignupOTP.objects.create(email=email, code=code)
        
        # Send email with OTP
        send_mail(
            'Your Signup OTP',
            f'Your OTP for signup is {code}. OTP is valid for 5 minutes.',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        
        return Response(
            {"message": "OTP sent to email."}, 
            status=status.HTTP_200_OK
        )


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from django.db import models
from django.contrib.auth import get_user_model

from api.models import PendingSignup, SignupOTP  # Adjust if your model paths differ

User = get_user_model()


class SignupView(APIView):
    """View for user signup with OTP verification."""

    def post(self, request):
        """
        Create a pending signup request after OTP verification.

        Returns:
            Success message if signup request was submitted
        """
        email = request.data.get("email")
        otp = request.data.get("otp")
        username = request.data.get("username", email)

        # Get all model field names excluding specific ones
        user_fields = [
            f.name for f in PendingSignup._meta.fields 
            if f.name not in ("id", "created_at", "is_approved", "approved_at", "username", "password", "email")
        ]

        # Define required fields for signup
        required_fields = ["first_name", "college_name", "role", "phone", "password"]
        missing = [field for field in required_fields if not request.data.get(field)]

        # Validate required fields
        if not email or not otp or missing:
            error_msg = "Email and OTP required." if not email or not otp else f"Missing fields: {', '.join(missing)}"
            return Response({"error": error_msg}, status=status.HTTP_400_BAD_REQUEST)

        # Check if email or username already exists
        if User.objects.filter(email=email).exists() or PendingSignup.objects.filter(email=email).exists():
            return Response({"error": "Email already taken."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists() or PendingSignup.objects.filter(username=username).exists():
            return Response({"error": "Username already taken."}, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP
        otp_entry = SignupOTP.objects.filter(email=email, code=otp).order_by('-created_at').first()
        if not otp_entry or (timezone.now() - otp_entry.created_at > timedelta(minutes=30)):
            if otp_entry:
                otp_entry.delete()
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare data for pending signup with type-safe conversions
        pending_data = {}
        for field in user_fields:
            value = request.data.get(field, "")
            model_field = PendingSignup._meta.get_field(field)

            # Handle Integer or Float fields
            if isinstance(model_field, (models.IntegerField, models.FloatField)):
                try:
                    value = int(value) if value not in ("", None) else 0
                except ValueError:
                    return Response({"error": f"Invalid value for '{field}'. Must be a number."}, status=400)

            # Handle Date or DateTime fields
            elif isinstance(model_field, (models.DateField, models.DateTimeField)):
                value = value or None  # Django will parse if valid, else error at DB level

            pending_data[field] = value

        # Set extra required fields
        pending_data['email'] = email
        pending_data['username'] = username
        pending_data['password'] = request.data.get("password")

        # Create or update pending signup
        PendingSignup.objects.update_or_create(
            email=email,
            defaults=pending_data
        )

        # Delete the used OTP
        otp_entry.delete()

        return Response(
            {"message": "Signup request submitted. Await admin approval."},
            status=status.HTTP_200_OK
        )

class ApproveSignupView(APIView):
    """View for listing and approving pending signup requests."""
    
    def get(self, request):
        """List all pending signup requests."""
        pending = PendingSignup.objects.filter(is_approved=False)
        serializer = PendingSignupSerializer(pending, many=True)
        return Response(serializer.data)
    
    def post(self, request, format=None):
        """
        Approve a pending signup request and create a user account.
        
        Returns:
            Success message if user was created
        """
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            pending = PendingSignup.objects.get(email=email, is_approved=False)
        except PendingSignup.DoesNotExist:
            return Response({"error": "Pending signup not found"}, status=status.HTTP_404_NOT_FOUND)

        # Prepare user data from pending signup
        user_data = {}
        for field in [f for f in User._meta.fields if f.name not in ("id", "last_login", "date_joined", "password")]:
            value = getattr(pending, field.name, "")

            # Handle None and empty values for date fields
            if value is None:
                value = ""
            if isinstance(field, (models.DateField, models.DateTimeField)) and value == "":
                value = None

            # Ensure boolean fields are True/False, not empty string
            if isinstance(field, models.BooleanField):
                if value in [True, False]:
                    user_data[field.name] = value
                elif str(value).lower() == "true":
                    user_data[field.name] = True
                elif str(value).lower() == "false":
                    user_data[field.name] = False
                else:
                    user_data[field.name] = False  # Default to False if empty or invalid
            else:
                user_data[field.name] = value

        # Set core user data
        user_data['username'] = pending.username
        user_data['email'] = pending.email
        user_data['is_superuser'] = False
        user_data['is_active'] = True
        user_data['is_staff'] = (pending.role.lower() == "staff")

        # Create the user account
        user = User.objects.create_user(**user_data)
        user.set_password(pending.password)
        user.save()

        # Mark pending signup as approved
        pending.is_approved = True
        pending.approved_at = timezone.now()
        pending.save()
        
        # Notify user via email
        send_mail(
            'Your Account Has Been Approved',
            f'Your account has been approved.\nUsername: {pending.username}',
            settings.EMAIL_HOST_USER,
            [pending.email],
            fail_silently=False,
        )
        
        # Clean up pending signup
        pending.delete()
        
        return Response({"message": "User approved"}, status=status.HTTP_200_OK)
    
    def delete(self, request, format=None):
        """
        Deny a pending signup request.
        
        Returns:
            Success message if request was denied
        """
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email required to deny signup"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            pending = PendingSignup.objects.get(email=email, is_approved=False)
        except PendingSignup.DoesNotExist:
            return Response({"error": "Pending signup not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Notify user via email
        send_mail(
            'Signup Request Denied',
            'Your signup request has been denied by the administrator.',
            settings.EMAIL_HOST_USER,
            [pending.email],
            fail_silently=False,
        )
        
        # Delete pending signup
        pending.delete()
        
        return Response({"message": "Pending signup request deleted"}, status=status.HTTP_200_OK)

class UserStatisticsView(APIView):
    """View for retrieving total users and new users statistics."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """
        Get statistics about total users and new users.
        
        Returns:
            - total_users: Total number of users in the system
            - new_users: Number of users created in the last 30 days
        """
        total_users = User.objects.count()
        thirty_days_ago = timezone.now() - timedelta(days=30)
        new_users = User.objects.filter(date_joined__gte=thirty_days_ago).count()

        return Response({
            "total_users": total_users,
            "new_users": new_users
        }, status=status.HTTP_200_OK)

#####################################
#          PROFILE VIEWS            #
#####################################

class ProfileView(APIView):
    """View for retrieving and updating the current user's profile."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """Get the authenticated user's profile data."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def put(self, request):
        """Update the authenticated user's profile data."""
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    """View for retrieving another user's profile."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request, username):
        """
        Get a user's profile data by username.
        
        Also includes jobs and events posted by this user.
        """
        # Verify authenticated with request
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
            
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Get user's basic profile
        user_serializer = UserSerializer(user)
        
        # Get user's posted jobs
        jobs = Jobs.objects.filter(user=user).order_by('-posted_on')[:5]
        jobs_serializer = JobsSerializer(jobs, many=True)
        
        # Get user's posted events
        events = Events.objects.filter(user=user).order_by('-uploaded_on')[:5]
        events_serializer = EventSerializer(events, many=True)
        
        # Get user's businesses
        businesses = BusinessDirectory.objects.filter(owner=user, is_active=True)[:5]
        businesses_serializer = BusinessDirectorySerializer(businesses, many=True)
        
        # Combine all data
        response_data = user_serializer.data
        response_data['posts'] = {
            'jobs': jobs_serializer.data,
            'events': events_serializer.data,
            'businesses': businesses_serializer.data
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
class BirthdayListView(APIView):
    """View for listing user birthdays in the upcoming 15 days."""
    # permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Get users whose birthdays are within the next 15 days."""
        today = timezone.now().date()
        users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True)

        upcoming_birthdays = []
        for user in users_with_birthdays:
            birth_month = user.date_of_birth.month
            birth_day = user.date_of_birth.day

            # Calculate next birthday, handle leap year issue
            try:
                next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
            except ValueError:
                # Handle Feb 29 on non-leap years by using Feb 28
                if birth_month == 2 and birth_day == 29:
                    next_birthday = timezone.datetime(today.year, 2, 28).date()
                else:
                    continue  # skip invalid dates

            if next_birthday < today:
                try:
                    next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                    else:
                        continue

            days_until_birthday = (next_birthday - today).days

            if 0 <= days_until_birthday <= 15:
                upcoming_birthdays.append({
                    'user': user,
                    'days_until_birthday': days_until_birthday
                })

        # Sort by days until birthday
        upcoming_birthdays.sort(key=lambda x: x['days_until_birthday'])

        users_ordered = [item['user'] for item in upcoming_birthdays]
        serializer = UserSerializer(users_ordered, many=True)

        response_data = []
        for i, user_data in enumerate(serializer.data):
            user_data['days_until_birthday'] = upcoming_birthdays[i]['days_until_birthday']
            response_data.append(user_data)

        return Response(response_data, status=status.HTTP_200_OK)
    
class DropdownFiltersView(APIView):
    """API to fetch distinct values for dropdown filters."""
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        filters_data = {
            "current_work": User.objects.exclude(current_work__isnull=True).exclude(current_work="").values_list("current_work", flat=True).distinct().order_by("current_work"),
            "college_name": User.objects.exclude(college_name__isnull=True).exclude(college_name="").values_list("college_name", flat=True).distinct().order_by("college_name"),
            "city": User.objects.exclude(city__isnull=True).exclude(city="").values_list("city", flat=True).distinct().order_by("city"),
            "state": User.objects.exclude(state__isnull=True).exclude(state="").values_list("state", flat=True).distinct().order_by("state"),
            "country": User.objects.exclude(country__isnull=True).exclude(country="").values_list("country", flat=True).distinct().order_by("country"),
            "role": User.objects.exclude(role__isnull=True).exclude(role="").values_list("role", flat=True).distinct().order_by("role"),
            "passed_out_year": User.objects.exclude(passed_out_year__isnull=True).exclude(passed_out_year="").values_list("passed_out_year", flat=True).distinct().order_by("passed_out_year"),
            "course": User.objects.exclude(course__isnull=True).exclude(course="").values_list("course", flat=True).distinct().order_by("course"),
        }

        # Convert QuerySets to lists for JSON serialization
        filters_data = {key: list(values) for key, values in filters_data.items()}

        return Response(filters_data, status=200)

class LatestMembersView(APIView):
    """View for listing recent members."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Get the 10 most recent Alumni members."""
        latest_members = User.objects.all().order_by('passed_out_year')[:10]
        serializer = UserSerializer(latest_members, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AlumniPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000
    
class AlumniAdminFilter(django_filters.FilterSet):
    roles_played = django_filters.CharFilter(method='filter_roles_played')
    Worked_in = django_filters.CharFilter(method='filter_Worked_in')

    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name', 'gender',
            'date_of_birth', 'current_work', 'college_name',
            'phone',  # REMOVE 'address' if not a model field!, 'chapter', 'salutation',
            'city', 'state', 'country', 'zip_code', 'role',
            'course_end_year', 'company', 'position', 'course', 'passed_out_year',
            # 'is_staff', 'is_active', 'is_superuser', 'chapter'
        ]

    def filter_roles_played(self, queryset, value):
        return queryset.filter(Q(roles_played__startswith=value) | Q(roles_played__icontains=value))

    def filter_Worked_in(self, queryset, value):
        return queryset.filter(Q(Worked_in__startswith=value) | Q(Worked_in__icontains=value))

class AlumniAdminFilterView(ListAPIView):
    """
    Admin view for filtering alumni in all possible ways.
    Supports filtering, search, ordering, and pagination.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = AlumniPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AlumniAdminFilter

    search_fields = [
        'username', 'first_name', 'last_name' #, 'current_work',
        # 'roles_played', 'Worked_in', 'college_name', 'phone', 'Address', 'city'
    ]
    ordering_fields = '__all__'
    ordering = ['first_name', 'last_name', 'username', 'college_name']

    def get_queryset(self):
        queryset = super().get_queryset()
        queryset = queryset.exclude(id=self.request.user.id)

        # Exact match for search query
        search_query = self.request.query_params.get('search', None)
        if search_query:
            queryset = queryset.filter(
            Q(first_name__icontains=search_query) | Q(last_name__icontains=search_query)
            )

        return queryset
#####################################
#           EVENT VIEWS             #
#####################################

class EventView(APIView):
    """View for listing and creating events."""
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """Get all events, ordered by upload date."""
        events = Events.objects.all().order_by('-uploaded_on')
        serializer = EventSerializer(events, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def post(self, request, *args, **kwargs):
        permission_classes = [permissions.IsAuthenticated]

        """
        Create a new event with optional images.
        
        Returns:
            The created event data
        """
        data = request.data.dict()
        # Remove 'images' from data to avoid type conflict in serializer validation
        data.pop('images', None)
        data['uploaded_by'] = request.user.role
        data['user'] = request.user.id 
        
        images = request.FILES.getlist('images')
        serializer = EventSerializer(data=data)
        
        if serializer.is_valid():
            event = serializer.save(user=request.user)
            
            # Save event images
            for img in images:
                EventImage.objects.create(event=event, image=img)
                
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EventDetailView(APIView):
    """View for retrieving, updating, and deleting a specific event."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        """Get an event by primary key or raise 404."""
        try:
            return Events.objects.get(pk=pk)
        except Events.DoesNotExist:
            raise Http404
            
    def get(self, request, pk):
        """Get a specific event by ID."""
        event = self.get_object(pk)
        serializer = EventSerializer(event)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def put(self, request, pk):
        """
        Update a specific event.
        
        Only the creator or staff/admin can update events.
        """
        event = self.get_object(pk)
        
        # Check permissions
        if event.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = EventSerializer(event, data=request.data, partial=True)
            if serializer.is_valid():
                event = serializer.save()
                
                # Update images if provided
                if request.FILES.getlist('images'):
                    # Delete old images
                    event.eventimage_set.all().delete()
                    
                    # Add new images
                    images = request.FILES.getlist('images')
                    for img in images:
                        EventImage.objects.create(event=event, image=img)
                        
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
    def delete(self, request, pk):
        """
        Delete a specific event.
        
        Only the creator or staff/admin can delete events.
        """
        event = self.get_object(pk)
        
        # Check permissions
        if event.user == request.user or request.user.role in ["Staff", "Admin"]:
            event.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)


#####################################
#           JOB VIEWS               #
#####################################

class JobListCreateView(APIView):
    """View for listing and creating jobs."""
    permission_classes = [permissions.AllowAny]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """Get all jobs, ordered by post date."""
        jobs = Jobs.objects.all().order_by('-posted_on')
        serializer = JobsSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def post(self, request):
        permission_classes = [permissions.IsAuthenticated]
        """
        Create a new job listing with optional images.
        
        Returns:
            The created job data
        """
        job_data = request.data.dict()  # Avoid deep-copying file objects
        images = request.FILES.getlist('images')
        job_data['uploaded_by'] = request.user.role
        
        serializer = JobsSerializer(data=job_data)
        if serializer.is_valid():
            job = serializer.save(user=request.user, role=request.user.role)
            
            # Save job images
            for image in images:
                JobImage.objects.create(job=job, image=image)
                
            updated_serializer = JobsSerializer(job)
            return Response(updated_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JobDetailView(APIView):
    """View for retrieving, updating, and deleting a specific job."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        """Get a job by primary key or raise 404."""
        try:
            return Jobs.objects.get(pk=pk)
        except Jobs.DoesNotExist:
            raise Http404
            
    def get(self, request, pk):
        """
        Get a specific job by ID and increment view count.
        
        Uses cache to prevent duplicate views from the same user.
        """
        job = self.get_object(pk)
        
        # Increment view count once per session
        cache_key = f"job_view_{request.user.id}_{job.id}"
        if not cache.get(cache_key):
            job.views += 1
            job.save(update_fields=["views"])
            cache.set(cache_key, True, 3600)  # Cache for 1 hour
            
        serializer = JobsSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def put(self, request, pk):
        """
        Update a specific job.
        
        Only the creator or staff/admin can update jobs.
        """
        job = self.get_object(pk)
        
        # Check permissions
        if job.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = JobsSerializer(job, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
    def delete(self, request, pk):
        """
        Delete a specific job.
        
        Only the creator or staff/admin can delete jobs.
        """
        job = self.get_object(pk)
        
        # Check permissions
        if job.user == request.user or request.user.role in ["Staff", "Admin"]:
            job.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)


class JobImagesView(APIView):
    """View for listing and adding images to a job."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, job_id):
        """Get all images for a specific job."""
        images = JobImage.objects.filter(job=job_id)
        serializer = JobImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def post(self, request, job_id):
        """
        Add an image to a specific job.
        
        Returns:
            The created image data
        """
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
    """View for listing and creating comments on a job."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, job_id):
        """Get all comments for a specific job."""
        comments = JobComment.objects.filter(job__id=job_id).order_by('-created_at')
        serializer = JobCommentSerializer(comments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def post(self, request, job_id):
        """
        Create a new comment on a specific job.
        
        Returns:
            The created comment data
        """
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
    """View for retrieving, updating, and deleting a specific comment."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self, pk):
        """Get a comment by primary key or raise 404."""
        try:
            return JobComment.objects.get(pk=pk)
        except JobComment.DoesNotExist:
            raise Http404
            
    def get(self, request, pk):
        """Get a specific comment by ID."""
        comment = self.get_object(pk)
        serializer = JobCommentSerializer(comment)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
    def put(self, request, pk):
        """
        Update a specific comment.
        
        Only the creator or staff/admin can update comments.
        """
        comment = self.get_object(pk)
        
        # Check permissions
        if comment.user == request.user or request.user.role in ["Staff", "Admin"]:
            serializer = JobCommentSerializer(comment, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
    def delete(self, request, pk):
        """
        Delete a specific comment.
        
        Only the creator or staff/admin can delete comments.
        """
        comment = self.get_object(pk)
        
        # Check permissions
        if comment.user == request.user or request.user.role in ["Staff", "Admin"]:
            comment.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)


class JobReactionView(APIView):
    """View for adding/removing reactions to jobs."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, job_id):
        """
        Add or remove a reaction (like) on a job.
        
        Payload should include {"reaction": {"like": 1}} to add a reaction
        or {"reaction": {"like": 0}} to remove it.
        
        Returns:
            Updated reaction counts for the job
        """
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


#####################################
#          ALBUM VIEWS             #
#####################################

class AlbumDetailView(APIView):
    """View for listing, creating, updating and deleting albums."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """Get all albums, ordered by ID (most recent first)."""
        albums = Album.objects.all().order_by("-id")
        serializer = AlbumSerializer(albums, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def get_object(self, pk):
        """Get an album by primary key or raise 404."""
        try:
            return Album.objects.get(pk=pk)
        except Album.DoesNotExist:
            raise Http404
    
    def post(self, request):
        """
        Create a new album with optional images.
        
        Returns:
            The created album data with images
        """
        album_data = request.data.dict()
        images = request.FILES.getlist('images')
        
        # Validate and save album
        serializer = AlbumSerializer(data=album_data)
        serializer.is_valid(raise_exception=True)
        album = serializer.save(user=request.user)
        
        # Save album images
        created_images = []
        for image in images:
            img_serializer = AlbumImageSerializer(data={'image': image, 'album': album.id})
            if img_serializer.is_valid():
                img_serializer.save(album=album)
                created_images.append(img_serializer.data)
            else:
                return Response(img_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Include images in response
        response_data = serializer.data
        response_data['images'] = created_images
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    def put(self, request, pk):
        """
        Update a specific album.
        
        Only the creator or staff/admin can update albums.
        """
        album = self.get_object(pk)
        
        # Check permissions
        if album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AlbumSerializer(album, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """
        Delete a specific album.
        
        Only the creator or staff/admin can delete albums.
        """
        album = self.get_object(pk)
        
        # Check permissions
        if album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        album.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AlbumImagesView(APIView):
    """View for managing images within an album."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        """Get an album image by primary key or raise 404."""
        try:
            return AlbumImage.objects.get(pk=pk)
        except AlbumImage.DoesNotExist:
            raise Http404
    
    def get(self, request, album_id):
        """Get all images for a specific album."""
        images = AlbumImage.objects.filter(album__id=album_id)
        serializer = AlbumImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, album_id):
        """
        Add images to a specific album.
        
        Returns:
            The created image data
        """
        try:
            album = Album.objects.get(id=album_id)
        except Album.DoesNotExist:
            return Response({"error": "Album not found"}, status=status.HTTP_404_NOT_FOUND)
        
        images = request.FILES.getlist('images')
        if not images:
            return Response({"error": "No Image provided"}, status=status.HTTP_204_NO_CONTENT)
        
        # Save all images
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
        """
        Update a specific album image.
        
        Only the album creator or staff/admin can update images.
        """
        album_image = self.get_object(album_id)
        
        # Check permissions
        if album_image.album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AlbumImageSerializer(album_image, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, album_id):
        """
        Delete a specific album image.
        
        Only the album creator or staff/admin can delete images.
        """
        album_image = self.get_object(album_id)
        
        # Check permissions
        if album_image.album.user != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        album_image.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


#####################################
#       HOME & UTILITY VIEWS        #
#####################################

class HomePageDataView(APIView):
    """View for aggregating data for the home page."""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """
        Get aggregated data for the home page:
        - Upcoming events
        - Latest album images
        - Latest members
        - Batch mates (users from same graduation year)
        - Chapter information
        - Featured news
        
        Returns:
            Aggregated data for home page display
        """
        now = timezone.now()
        today = now.date()
        
        # Upcoming Events
        upcoming_events = Events.objects.all().order_by('from_date_time')[:3]
        events_serializer = EventSerializer(upcoming_events, many=True)
        
        # Latest Album Images 
        latest_album_images = Album.objects.all().order_by('-id')[:5]
        album_images_serializer = AlbumSerializer(latest_album_images, many=True)
        
        # Latest Members
        users_with_photos = User.objects.filter(profile_photo__isnull=False).exclude(profile_photo='').order_by('-id')[:3]
        # latest_members = list(users_with_photos)
        members_serializer = UserSerializer(users_with_photos, many=True)
        batch_mates_serializer = None
        if request.user.is_authenticated:
        # Batch Mates - Get users from same passed_out_year as current user
            batch_mates = []
            if request.user.passed_out_year:
                batch_mates = User.objects.filter(
                    passed_out_year=request.user.passed_out_year
                ).exclude(id=request.user.id).order_by('first_name')[:10]
            batch_mates_serializer = UserSerializer(batch_mates, many=True)
            
        batch_mates_data = batch_mates_serializer.data if batch_mates_serializer else []
        # Chapters - Get all unique chapters and count of users in each
        chapters = User.objects.exclude(chapter='').values('chapter').annotate(
            member_count=Count('id')
        ).order_by('-member_count')
        
        # Add featured news
        featured_news = NewsRoom.objects.all().order_by('-published_on')[:3]
        news_serializer = NewsRoomSerializer(featured_news, many=True)
        total_users = User.objects.count()
        thirty_days_ago = timezone.now() - timedelta(days=30)
        new_users = User.objects.filter(date_joined__gte=thirty_days_ago).count()
        # Count upcoming events
        upcoming_events_count = Events.objects.filter(from_date_time__gte=datetime.now()).count()
        # Count albums
        albums_count = Album.objects.count()
        # Compile and return response
        return Response({
            'upcoming_events': events_serializer.data,
            'latest_album_images': album_images_serializer.data,
            'latest_members': members_serializer.data,
            'batch_mates': batch_mates_data,
            'chapters': chapters,
            'featured_news': news_serializer.data,
            "total_users": total_users,
            "new_users": new_users ,
            "upcoming_events": upcoming_events_count,
            "albums_count": albums_count,
            
        }, status=status.HTTP_200_OK)


class MyPostsView(APIView):
    """View for listing the current user's posts."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all jobs and events created by the authenticated user."""
        # Get user's jobs
        jobs = Jobs.objects.filter(user=request.user).order_by('-posted_on')
        jobs_serializer = JobsSerializer(jobs, many=True)
        
        # Get user's events
        events = Events.objects.filter(user=request.user).order_by('-uploaded_on')
        events_serializer = EventSerializer(events, many=True)
        
        # Return combined data
        return Response({
            "jobs": jobs_serializer.data,
            "events": events_serializer.data
        }, status=status.HTTP_200_OK)


class ImportMembersAPIView(APIView):
    """View for importing members from a CSV file."""
    
    def post(self, request):
        """
        Import registered members from members.csv into the CustomUser model.
        
        Uses email as username and date of birth as password. Maps all available 
        fields from the CSV to the CustomUser model.
        
        Returns:
            Statistics about the import operation
        """
        User = get_user_model()
        csv_path = os.path.join(settings.BASE_DIR, 'members.csv')
        created, updated, skipped = [], [], []
        
        with open(csv_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Extract core data
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
                
                # Process JSON fields
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
                    # Update existing user
                    user = User.objects.get(email=email)
                    for k, v in user_data.items():
                        setattr(user, k, v)
                    if password:
                        user.set_password(password)
                    user.save()
                    updated.append(email)
                except User.DoesNotExist:
                    # Create new user
                    user = User(**user_data)
                    user.set_password(password)
                    user.save()
                    created.append(email)
                except Exception as e:
                    skipped.append(f"{email} ({str(e)})")

        # Return import statistics
        return Response({
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "message": f"{len(created)} users created, {len(updated)} updated, {len(skipped)} skipped."
        }, status=status.HTTP_201_CREATED)


#####################################
#       USER LOCATION VIEWS         #
#####################################

class UserLocationListCreateAPIView(generics.ListCreateAPIView):
    """View for listing and creating user location entries."""
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all user locations."""
        return user_location.objects.all()
    
    def perform_create(self, serializer):
        """Save the current user as the owner of the location."""
        serializer.save(user=self.request.user)


class UserLocationRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    """View for managing a specific user location."""
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'id'
    
    def get_queryset(self):
        """Only allow access to the user's own locations."""
        return user_location.objects.filter(user=self.request.user)


class UserLocationsearchAPIView(generics.ListAPIView):
    """View for searching user locations by name."""
    serializer_class = UserLocationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Search for locations by user name."""
        name = self.request.query_params.get("name", "")
        if name:
            return user_location.objects.filter(
                Q(user__first_name__icontains=name) |
                Q(user__last_name__icontains=name) |
                Q(user__username__icontains=name)
            )
        return user_location.objects.none()

    def list(self, _request, *_args, **_kwargs):
        """Return user locations as simple values."""
        queryset = self.get_queryset()
        results = list(queryset.values())
        return Response(results, status=status.HTTP_200_OK)


#####################################
#     BUSINESS DIRECTORY VIEWS      #
#####################################

class BusinessDirectoryListCreateView(APIView):
    """View for listing and creating business directory entries."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """List all active businesses."""
        businesses = BusinessDirectory.objects.filter(is_active=True).order_by('-created_at')
        serializer = BusinessDirectorySerializer(businesses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """
        Create a new business listing with optional images and logo.
        
        Returns:
            The created business data
        """
        business_data = request.data.dict() if hasattr(request.data, 'dict') else request.data
        
        # Handle logo if provided
        logo = request.FILES.get('logo')
        if logo:
            business_data['logo'] = logo
            
        # Convert JSON string fields to Python objects
        for json_field in ['social_media', 'keywords']:
            if json_field in business_data and isinstance(business_data[json_field], str):
                try:
                    business_data[json_field] = json.loads(business_data[json_field])
                except json.JSONDecodeError:
                    return Response(
                        {"error": f"Invalid JSON format for {json_field}"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
        
        # Create business
        serializer = BusinessDirectorySerializer(data=business_data)
        if serializer.is_valid():
            business = serializer.save(owner=request.user)
            
            # Handle multiple images if provided
            images = request.FILES.getlist('images')
            for img in images:
                BusinessImage.objects.create(
                    business=business, 
                    image=img, 
                    caption=request.data.get('caption', '')
                )
            
            # Re-serialize with images included
            updated_serializer = BusinessDirectorySerializer(business)
            return Response(updated_serializer.data, status=status.HTTP_201_CREATED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BusinessDirectoryDetailView(APIView):
    """View for managing a specific business listing."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        """Get a business by primary key or raise 404."""
        try:
            return BusinessDirectory.objects.get(pk=pk)
        except BusinessDirectory.DoesNotExist:
            raise Http404
    
    def get(self, request, pk):
        """Get a specific business by ID."""
        business = self.get_object(pk)
        serializer = BusinessDirectorySerializer(business)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """
        Update a specific business.
        
        Only the owner or staff/admin can update businesses.
        """
        business = self.get_object(pk)
        
        # Check permissions
        if business.owner != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        business_data = request.data.dict() if hasattr(request.data, 'dict') else request.data
        
        # Handle logo if provided
        if 'logo' in request.FILES:
            business_data['logo'] = request.FILES.get('logo')
            
        # Process JSON fields
        for json_field in ['social_media', 'keywords']:
            if json_field in business_data and isinstance(business_data[json_field], str):
                try:
                    business_data[json_field] = json.loads(business_data[json_field])
                except json.JSONDecodeError:
                    return Response(
                        {"error": f"Invalid JSON format for {json_field}"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
        
        # Update business
        serializer = BusinessDirectorySerializer(business, data=business_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """
        Delete a specific business.
        
        Only the owner or staff/admin can delete businesses.
        """
        business = self.get_object(pk)
        
        # Check permissions
        if business.owner != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        business.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class BusinessImagesView(APIView):
    """View for managing images for a business."""
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        """Get a business image by primary key or raise 404."""
        try:
            return BusinessImage.objects.get(pk=pk)
        except BusinessImage.DoesNotExist:
            raise Http404
    
    def get(self, request, business_id):
        """List all images for a specific business."""
        images = BusinessImage.objects.filter(business_id=business_id)
        serializer = BusinessImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, business_id):
        """
        Add images to a specific business.
        
        Only the owner or staff/admin can add images.
        
        Returns:
            The created image data
        """
        try:
            business = BusinessDirectory.objects.get(id=business_id)
        except BusinessDirectory.DoesNotExist:
            return Response({"error": "Business not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions
        if business.owner != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        images = request.FILES.getlist('images')
        if not images:
            return Response({"error": "No images provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Save all images
        created_images = []
        for img in images:
            caption = request.data.get('caption', '')
            image = BusinessImage.objects.create(business=business, image=img, caption=caption)
            serializer = BusinessImageSerializer(image)
            created_images.append(serializer.data)
        
        return Response(created_images, status=status.HTTP_201_CREATED)
    
    def delete(self, request, business_id):
        """
        Delete a specific business image.
        
        Only the business owner or staff/admin can delete images.
        """
        # In this case business_id parameter is actually the image ID
        image = self.get_object(business_id)
        business = image.business
        
        # Check permissions
        if business.owner != request.user and request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        image.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class BusinessCategoriesView(APIView):
    """View for listing business categories with counts."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all unique business categories with counts."""
        categories = BusinessDirectory.objects.exclude(category='') \
                                           .values('category') \
                                           .annotate(count=Count('id'))
        return Response(categories, status=status.HTTP_200_OK)
    
class BusinessSearchView(generics.ListAPIView):
    serializer_class = BusinessDirectorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Search businesses by various parameters"""
        queryset = BusinessDirectory.objects.filter(is_active=True)
        
        # Get search parameters
        query = self.request.query_params.get('q', '')
        category = self.request.query_params.get('category', '')
        city = self.request.query_params.get('city', '')
        state = self.request.query_params.get('state', '')
        
        # Filter by text search
        if query:
            queryset = queryset.filter(
                Q(business_name__icontains=query) |
                Q(description__icontains=query) |
                Q(keywords__contains=query)
            )
        
        # Filter by category
        if category:
            queryset = queryset.filter(category__iexact=category)
            
        # Filter by location
        if city:
            queryset = queryset.filter(city__icontains=city)
        if state:
            queryset = queryset.filter(state__icontains=state)
            
        # Add entrepreneur filter (users with is_entrepreneur flag)
        entrepreneur = self.request.query_params.get('entrepreneur', '')
        if entrepreneur.lower() == 'true':
            queryset = queryset.filter(owner__is_entrepreneur=True)
            
        return queryset.order_by('-created_at')

#####################################        
# ----- NewsRoom Endpoints -----    #
#####################################
class NewsRoomListCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get(self, request):
        """List all published news articles, optionally filtered by category"""
        queryset = NewsRoom.objects.filter(status='published')
        
        # Filter by category if specified
        category = request.query_params.get('category')
        if category:
            queryset = queryset.filter(category__iexact=category)
            
        # Filter featured articles if specified
        featured = request.query_params.get('featured')
        if featured and featured.lower() == 'true':
            queryset = queryset.filter(featured=True)
        
        serializer = NewsRoomSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)   
    def post(self, request):
        """Create a new news article"""
        # Only staff or admin can create news
        # if request.user.role not in ["Staff", "Admin"]:
        #     return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
            
        news_data = request.data.dict() if hasattr(request.data, 'dict') else request.data
        
        
        # Handle thumbnail if provided
        thumbnail = request.FILES.get('thumbnail')
        if thumbnail:
            news_data['thumbnail'] = thumbnail
        
        serializer = NewsRoomSerializer(data=news_data)
        if serializer.is_valid():
            news_article = serializer.save(user=request.user)
            
            # Handle multiple images if provided
            images = request.FILES.getlist('images')
            for img in images:
                caption = request.data.get('caption', '')
                NewsImage.objects.create(news_article=news_article, image=img, caption=caption)
            
            # Re-serialize with images included
            updated_serializer = NewsRoomSerializer(news_article)
            return Response(updated_serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class NewsRoomDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        try:
            return NewsRoom.objects.get(pk=pk)
        except NewsRoom.DoesNotExist:
            raise Http404
    
    def get(self, request, pk):
        """Retrieve a news article and increment view count"""
        news_article = self.get_object(pk)
        serializer = NewsRoomSerializer(news_article)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        """Update a news article"""
        news_article = self.get_object(pk)
        
        # Only the author, staff, or admin can update
        if news_article.user != request.user or request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        news_data = request.data.dict() if hasattr(request.data, 'dict') else request.data
        
        # Handle thumbnail if provided
        if 'thumbnail' in request.FILES:
            news_data['thumbnail'] = request.FILES.get('thumbnail')
        
        serializer = NewsRoomSerializer(news_article, data=news_data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """Delete a news article"""
        news_article = self.get_object(pk)
        
        # Only the author, staff, or admin can delete
        if news_article.user != request.user or request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        news_article.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class NewsImagesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    
    def get_object(self, pk):
        try:
            return NewsImage.objects.get(pk=pk)
        except NewsImage.DoesNotExist:
            raise Http404
    
    def get(self, request, news_id):
        """List images for a news article"""
        images = NewsImage.objects.filter(news_article_id=news_id)
        serializer = NewsImageSerializer(images, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request, news_id):
        """Add images to a news article"""
        try:
            news_article = NewsRoom.objects.get(id=news_id)
        except NewsRoom.DoesNotExist:
            return Response({"error": "News article not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Check permissions
        if news_article.user != request.user or request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        images = request.FILES.getlist('images')
        if not images:
            return Response({"error": "No images provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        created_images = []
        for img in images:
            caption = request.data.get('caption', '')
            image = NewsImage.objects.create(news_article=news_article, image=img, caption=caption)
            serializer = NewsImageSerializer(image)
            created_images.append(serializer.data)
        
        return Response(created_images, status=status.HTTP_201_CREATED)
    
    def delete(self, request, news_id):
        """Delete an image"""
        # In this case news_id parameter is actually the image ID
        image = self.get_object(news_id)
        news_article = image.news_article
        
        # Check permissions
        if news_article.user != request.user or request.user.role not in ["Staff", "Admin"]:
            return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        image.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class NewsCategoriesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get all unique news categories with counts"""
        from django.db.models import Count
        categories = NewsRoom.objects.exclude(category='') \
                                    .values('category') \
                                    .annotate(count=Count('id')) \
                                    .order_by('-count')
        return Response(categories, status=status.HTTP_200_OK)

from django.core.mail import EmailMessage
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

class SendEmailAPIView(APIView):
    """API to send emails with media attachments."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Send an email to the specified recipients, all users, or users by role.

        Payload:
        - subject: Email subject
        - body: Email body
        - send_to_all: Boolean flag to send email to all users
        - role: Role to filter recipients (e.g., 'Alumni', 'Staff')
        - recipients: List of recipient email addresses (optional if send_to_all or role is provided)
        - attachments: List of files to attach (optional)

        Returns:
            Success or error message
        """
        subject = request.data.get('subject')
        body = request.data.get('body')
        send_to_all = request.data.get('send_to_all', False)
        role = request.data.get('role', None)
        recipients = request.data.get('recipients', [])
        attachments = request.FILES.getlist('attachments')

        if not subject or not body:
            return Response(
                {"error": "Subject and body are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Retrieve all user emails if send_to_all is True
        if send_to_all:
            recipients = list(User.objects.values_list('email', flat=True))
        elif role:
            # Filter users by role
            recipients = list(User.objects.filter(role=role).values_list('email', flat=True))

        if not recipients:
            return Response(
                {"error": "No recipients found."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            email = EmailMessage(
                subject=subject,
                body=body,
                to=recipients
            )

            # Attach files if provided
            for attachment in attachments:
                email.attach(attachment.name, attachment.read(), attachment.content_type)

            email.send()
            return Response({"message": "Email sent successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class EmailSuggestionAPIView(APIView):
    """API to provide email suggestions while typing."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Suggest emails based on the query.

        Query Parameters:
        - query: Partial email string to search for

        Returns:
            List of matching email suggestions
        """
        query = request.query_params.get('query', '').strip()
        if not query:
            return Response({"error": "Query parameter is required."}, status=400)

        # Filter emails based on the query
        suggestions = User.objects.filter(email__icontains=query).values_list('email', flat=True)[:10]
        return Response({"suggestions": list(suggestions)}, status=200)

import pandas as pd
from datetime import datetime
from .models import CustomUser

def map_and_save_users(csv_path):
    # Load CSV data
    data = pd.read_csv(csv_path)

    for _, row in data.iterrows():
        try:
            dob_str = str(row.get("Date of Birth")).strip()

            # Skip if DOB is missing or invalid
            if not dob_str or dob_str.lower() in ["nan", "null"]:
                print(f"❌ Skipped user due to missing DOB: {row.get('email_id')}")
                continue

            # Parse DOB (auto-detect format)
            dob = pd.to_datetime(dob_str, errors='raise', dayfirst=False)
            password = dob.strftime("%d%m%Y")  # Convert to DDMMYYYY

            # Clean and prepare fields
            email = row.get("email_id", "").strip()
            name = row.get("Name", "").strip()
            salutation = row.get("Salutation", "").strip() if pd.notna(row.get("Salutation")) else None
            gender = row.get("Gender", "").strip() if pd.notna(row.get("Gender")) else "Nil"
            course = row.get("course", "").strip()
            role = row.get("role", "Alumni").strip()

            # Build user data
            user_data = {
                "username": email,
                "first_name": name,
                "salutation": salutation,
                "is_active": True,
                "is_staff": role.lower() in ["staff", "admin"],
                "is_superuser": role.lower() == "admin",
                "gender": gender,
                "date_of_birth": dob,
                "course": course,
                "email": email,
                "role": role,
            }

            # Create or update user
            user, created = CustomUser.objects.update_or_create(
                username=email,
                defaults=user_data
            )

            if created:
                user.set_password(password)
                user.save()
                print(f"[CREATED] {email} | Name: {name} | Password: {password}")
            else:
                print(f"[UPDATED] {email} | Name: {name}")

        except Exception as e:
            print(f"[ERROR] {row.get('email_id')} | {e}")

    print("✅ Data mapping and saving completed.")

# Example usage
csv_path = "d:\\alumini\\registered_users_with_roles.csv"
map_and_save_users(csv_path)
