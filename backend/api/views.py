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
import re
import pandas as pd
import django_filters
from datetime import datetime, timedelta
from django.db import models
from django.http import Http404
from django.conf import settings
from django.utils import timezone
from django.shortcuts import render
from django.core.cache import cache
from django.db.models import Q, Count
from django.core.mail import send_mail, EmailMessage
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework import status, permissions, generics
from rest_framework.generics import ListAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.parsers import MultiPartParser, FormParser

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

# Utility functions
def process_boolean_field(value):
    """Convert string values to proper boolean values."""
    if isinstance(value, str):
        value = value.strip().lower()
        if value in ('', 'none', 'null', 'false', '0', 'no'):
            return False
        elif value in ('true', '1', 'yes', 'on'):
            return True
    return bool(value) if value else False


def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp, purpose="signup"):
    """Send OTP email with enhanced professional and friendly formatting."""
    from django.template.loader import render_to_string
    
    # Enhanced email content based on purpose
    if purpose == "signup":
        subject = "🎓 Welcome to Alumni Portal - Verify Your Account"
        html_message = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
            <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #2c3e50; margin: 0;">Welcome to Alumni Portal! 🎉</h2>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Hello there! 👋
                </p>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    We're excited to have you join our alumni community! To complete your registration, 
                    please use the verification code below:
                </p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <div style="background-color: #3498db; color: white; font-size: 32px; font-weight: bold; 
                                padding: 20px; border-radius: 8px; letter-spacing: 8px; display: inline-block;">
                        {otp}
                    </div>
                </div>
                
                <div style="background-color: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="color: #2980b9; margin: 0; font-size: 14px;">
                        ⏰ <strong>Important:</strong> This code will expire in 30 minutes for your security.
                    </p>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    If you didn't request this verification, please ignore this email or contact our support team.
                </p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                    <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                        Best regards,<br>
                        <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                    </p>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 20px;">
                <p style="color: #7f8c8d; font-size: 12px;">
                    This is an automated message. Please do not reply to this email.
                </p>
            </div>
        </div>
        """
        
        plain_message = f"""
        Welcome to Alumni Portal! 🎉
        
        Hello there!
        
        We're excited to have you join our alumni community! To complete your registration, 
        please use the verification code below:
        
        Your Verification Code: {otp}
        
        ⏰ Important: This code will expire in 30 minutes for your security.
        
        If you didn't request this verification, please ignore this email or contact our support team.
        
        Best regards,
        The Alumni Portal Team
        
        ---
        This is an automated message. Please do not reply to this email.
        """
        
    elif purpose == "login":
        subject = "🔐 Alumni Portal - Login Verification Code"
        html_message = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
            <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #2c3e50; margin: 0;">Login Verification 🔐</h2>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Hello! 👋
                </p>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    We received a request to sign in to your Alumni Portal account. 
                    Please use the verification code below to complete your login:
                </p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <div style="background-color: #27ae60; color: white; font-size: 32px; font-weight: bold; 
                                padding: 20px; border-radius: 8px; letter-spacing: 8px; display: inline-block;">
                        {otp}
                    </div>
                </div>
                
                <div style="background-color: #d5f4e6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="color: #27ae60; margin: 0; font-size: 14px;">
                        ⏰ <strong>Security Note:</strong> This code will expire in 30 minutes.
                    </p>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    If this wasn't you, please secure your account immediately and contact our support team.
                </p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                    <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                        Stay secure,<br>
                        <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                    </p>
                </div>
            </div>
        </div>
        """
        
        plain_message = f"""
        Login Verification 🔐
        
        Hello!
        
        We received a request to sign in to your Alumni Portal account. 
        Please use the verification code below to complete your login:
        
        Your Verification Code: {otp}
        
        ⏰ Security Note: This code will expire in 30 minutes.
        
        If this wasn't you, please secure your account immediately and contact our support team.
        
        Stay secure,
        The Alumni Portal Team
        """
        
    else:
        # Generic template for other purposes
        subject = f"🎓 Alumni Portal - Your {purpose.title()} Code"
        html_message = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
            <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #2c3e50; margin: 0;">Alumni Portal Verification</h2>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Hello! 👋
                </p>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Here's your verification code for {purpose}:
                </p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <div style="background-color: #9b59b6; color: white; font-size: 32px; font-weight: bold; 
                                padding: 20px; border-radius: 8px; letter-spacing: 8px; display: inline-block;">
                        {otp}
                    </div>
                </div>
                
                <div style="background-color: #f4e8f8; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="color: #8e44ad; margin: 0; font-size: 14px;">
                        ⏰ <strong>Note:</strong> This code expires in 30 minutes for security.
                    </p>
                </div>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                    <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                        Best regards,<br>
                        <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                    </p>
                </div>
            </div>
        </div>
        """
        
        plain_message = f"""
        Alumni Portal Verification
        
        Hello!
        
        Here's your verification code for {purpose}:
        
        Your Verification Code: {otp}
        
        ⏰ Note: This code expires in 30 minutes for security.
        
        Best regards,
        The Alumni Portal Team
        """
    
    # Send both HTML and plain text versions
    try:
        email_message = EmailMessage(
            subject=subject,
            body=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[email],
        )
        email_message.attach_alternative(html_message, "text/html")
        email_message.send(fail_silently=False)
    except Exception:
        # Fallback to simple send_mail if EmailMessage fails
        send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [email], fail_silently=False)


def send_password_reset_email(email, user_name, reset_link):
    """Send password reset email with enhanced professional formatting."""
    subject = "🔑 Reset Your Alumni Portal Password"
    
    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #2c3e50; margin: 0;">Password Reset Request 🔑</h2>
            </div>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                Hello {user_name}! 👋
            </p>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                We received a request to reset your Alumni Portal password. Don't worry, it happens to the best of us! 
                Click the button below to create a new password:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}" style="background-color: #e74c3c; color: white; padding: 15px 30px; 
                   text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    🔄 Reset My Password
                </a>
            </div>
            
            <div style="background-color: #fff5f5; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #e74c3c;">
                <p style="color: #c0392b; margin: 0; font-size: 14px;">
                    <strong>🛡️ Security Notice:</strong> This link will expire in 24 hours for your protection.
                </p>
            </div>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                If the button doesn't work, you can copy and paste this link into your browser:
            </p>
            
            <div style="background-color: #f8f9fa; padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace; font-size: 12px; color: #6c757d;">
                {reset_link}
            </div>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6; margin-top: 20px;">
                <strong>Didn't request this?</strong> No worries! Your password is still secure. 
                You can safely ignore this email, or contact our support team if you have concerns.
            </p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                    Stay secure,<br>
                    <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                </p>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <p style="color: #7f8c8d; font-size: 12px;">
                This is an automated security message. Please do not reply to this email.
            </p>
        </div>
    </div>
    """
    
    plain_message = f"""
    Password Reset Request 🔑
    
    Hello {user_name}!
    
    We received a request to reset your Alumni Portal password. Don't worry, it happens to the best of us!
    
    Click the link below to create a new password:
    {reset_link}
    
    🛡️ Security Notice: This link will expire in 24 hours for your protection.
    
    Didn't request this? No worries! Your password is still secure. 
    You can safely ignore this email, or contact our support team if you have concerns.
    
    Stay secure,
    The Alumni Portal Team
    
    ---
    This is an automated security message. Please do not reply to this email.
    """
    
    try:
        email_message = EmailMessage(
            subject=subject,
            body=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[email],
        )
        email_message.attach_alternative(html_message, "text/html")
        email_message.send(fail_silently=False)
    except Exception:
        # Fallback to simple send_mail
        send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [email], fail_silently=False)


def send_approval_notification_email(email, user_name, login_url):
    """Send account approval notification with welcoming content."""
    subject = "🎉 Welcome to Alumni Portal - Your Account is Approved!"
    
    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #27ae60; margin: 0;">🎉 Account Approved! Welcome Aboard! 🎉</h2>
            </div>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                Dear {user_name}, 👋
            </p>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                Fantastic news! Your Alumni Portal account has been approved and is now active. 
                We're thrilled to welcome you to our vibrant alumni community! 🌟
            </p>
            
            <div style="background-color: #d5f4e6; padding: 20px; border-radius: 8px; margin: 25px 0; text-align: center;">
                <h3 style="color: #27ae60; margin: 0 0 15px 0;">🚀 You can now:</h3>
                <ul style="color: #2c3e50; text-align: left; margin: 0; padding-left: 20px;">
                    <li>Connect with fellow alumni worldwide 🌍</li>
                    <li>Access exclusive job opportunities 💼</li>
                    <li>Join exciting alumni events 🎪</li>
                    <li>Share your success stories 📖</li>
                    <li>Network and grow professionally 📈</li>
                </ul>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{login_url}" style="background-color: #27ae60; color: white; padding: 15px 30px; 
                   text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    🎯 Start Exploring Now
                </a>
            </div>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                <strong>Getting Started Tips:</strong> 📝
            </p>
            <ul style="color: #34495e; line-height: 1.8;">
                <li>Complete your profile to connect with more alumni</li>
                <li>Update your professional information</li>
                <li>Browse upcoming events in your area</li>
                <li>Check out the latest job postings</li>
            </ul>
            
            <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                Need help getting started? Our support team is here to assist you every step of the way! 💪
            </p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                    Welcome to the family! 🤗<br>
                    <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                </p>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <p style="color: #7f8c8d; font-size: 12px;">
                Ready to reconnect? Log in and start your alumni journey today!
            </p>
        </div>
    </div>
    """
    
    plain_message = f"""
    🎉 Account Approved! Welcome Aboard! 🎉
    
    Dear {user_name},
    
    Fantastic news! Your Alumni Portal account has been approved and is now active. 
    We're thrilled to welcome you to our vibrant alumni community! 🌟
    
    🚀 You can now:
    • Connect with fellow alumni worldwide 🌍
    • Access exclusive job opportunities 💼
    • Join exciting alumni events 🎪
    • Share your success stories 📖
    • Network and grow professionally 📈
    
    Start exploring: {login_url}
    
    📝 Getting Started Tips:
    • Complete your profile to connect with more alumni
    • Update your professional information
    • Browse upcoming events in your area
    • Check out the latest job postings
    
    Need help getting started? Our support team is here to assist you every step of the way! 💪
    
    Welcome to the family! 🤗
    The Alumni Portal Team
    
    ---
    Ready to reconnect? Log in and start your alumni journey today!
    """
    
    try:
        email_message = EmailMessage(
            subject=subject,
            body=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[email],
        )
        email_message.attach_alternative(html_message, "text/html")
        email_message.send(fail_silently=False)
    except Exception:
        send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [email], fail_silently=False)


def send_notification_email(email, subject, title, message, call_to_action=None, cta_url=None):
    """Send general notification email with professional formatting."""
    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #2c3e50; margin: 0;">{title}</h2>
            </div>
            
            <div style="color: #34495e; font-size: 16px; line-height: 1.6;">
                {message}
            </div>
            
            {f'''
            <div style="text-align: center; margin: 30px 0;">
                <a href="{cta_url}" style="background-color: #3498db; color: white; padding: 15px 30px; 
                   text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    {call_to_action}
                </a>
            </div>
            ''' if call_to_action and cta_url else ''}
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                    Best regards,<br>
                    <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                </p>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <p style="color: #7f8c8d; font-size: 12px;">
                This is an automated message from Alumni Portal.
            </p>
        </div>
    </div>
    """
    
    # Create plain text version
    plain_message = f"""
    {title}
    
    {message}
    
    {f'{call_to_action}: {cta_url}' if call_to_action and cta_url else ''}
    
    Best regards,
    The Alumni Portal Team
    
    ---
    This is an automated message from Alumni Portal.
    """
    
    try:
        email_message = EmailMessage(
            subject=subject,
            body=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[email],
        )
        email_message.attach_alternative(html_message, "text/html")
        email_message.send(fail_silently=False)
    except Exception:
        send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [email], fail_silently=False)


# Base view classes for common functionality
class BaseAuthenticatedView(APIView):
    """Base view with authentication requirement."""
    permission_classes = [permissions.IsAuthenticated]


class BaseMultiPartView(BaseAuthenticatedView):
    """Base view with authentication and multipart parsing."""
    parser_classes = (MultiPartParser, FormParser)


class BaseObjectRetrievalMixin:
    """Mixin for common object retrieval pattern."""
    
    def get_object_or_404(self, model, **kwargs):
        """Get object or raise 404."""
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404


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

        if user and user.role in ['Admin', 'Staff']:
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
        reset_link = request.build_absolute_uri(f"/api/reset-password/?uid={uid}&token={token}")
        
        # Send enhanced password reset email
        user_name = user.first_name or user.username
        send_password_reset_email(email, user_name, reset_link)
        
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
    permission_classes = [permissions.AllowAny]
    
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
            
        # Generate and save OTP
        code = generate_otp()
        SignupOTP.objects.create(email=email, code=code)
        
        # Send email with OTP
        send_otp_email(email, code, "signup")
        
        return Response(
            {"message": "OTP sent to email."}, 
            status=status.HTTP_200_OK
        )


class SignupView(BaseAuthenticatedView):
    """View for user signup with OTP verification."""
    permission_classes = [permissions.AllowAny]  # Override base class

    def _convert_field_value(self, field_name, value, model_field):
        """Convert field value based on model field type."""
        # Handle boolean fields - convert empty strings to False
        if isinstance(model_field, models.BooleanField):
            if value == "":
                return False
            elif isinstance(value, str):
                return value.lower() in ('true', '1', 'yes', 'on')
            return bool(value)

        # Handle Integer or Float fields
        elif isinstance(model_field, (models.IntegerField, models.FloatField)):
            if value in ("", None):
                return 0
            try:
                return int(value) if isinstance(model_field, models.IntegerField) else float(value)
            except ValueError:
                raise ValueError(f"Invalid value for '{field_name}'. Must be a number.")

        # Handle Date or DateTime fields
        elif isinstance(model_field, (models.DateField, models.DateTimeField)):
            return value or None

        return value

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
        excluded_fields = ("id", "created_at", "is_approved", "approved_at", "username", "password", "email")
        user_fields = [
            f.name for f in PendingSignup._meta.fields 
            if f.name not in excluded_fields
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
            
            try:
                pending_data[field] = self._convert_field_value(field, value, model_field)
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Set extra required fields
        pending_data.update({
            'email': email,
            'username': username,
            'password': request.data.get("password"),
            'is_active': True
        })

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
        
class PendingSignupPagination(PageNumberPagination):
    page_size = 30
    page_size_query_param = 'page_size'
    max_page_size = 100

class ApproveSignupView(APIView):
    """View for listing and approving pending signup requests."""
    
    def get(self, request):
        """List all pending signup requests with pagination."""
        pending = PendingSignup.objects.filter(is_approved=False, is_active=True).order_by('-created_at')

        # Apply pagination
        paginator = PendingSignupPagination()
        paginated_pending = paginator.paginate_queryset(pending, request)
        
        if paginated_pending is not None:
            serializer = PendingSignupSerializer(paginated_pending, many=True)
            return paginator.get_paginated_response(serializer.data)
        
        # Fallback without pagination
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
        
        # Send enhanced approval notification email
        user_name = user.first_name or user.username
        login_url = "https://karpagamalumni.in/login/"
        send_approval_notification_email(pending.email, user_name, login_url)
        
        # Clean up pending signup
        pending.delete()
        
        return Response({"message": "User approved and notified"}, status=status.HTTP_200_OK)
    
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
            
        # Send enhanced denial notification email
        user_name = pending.first_name or "Dear Applicant"
        subject = "📋 Alumni Portal - Signup Request Update"
        
        html_message = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
            <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #2c3e50; margin: 0;">Alumni Portal Application Update</h2>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Hello {user_name}, 👋
                </p>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Thank you for your interest in joining our Alumni Portal community. 
                    After careful review, we are unable to approve your application at this time.
                </p>
                
                <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                    <p style="color: #856404; margin: 0; font-size: 14px;">
                        <strong>📝 What's Next?</strong> You may reapply in the future or contact our support team 
                        if you believe this decision was made in error.
                    </p>
                </div>
                
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    We appreciate your understanding and wish you all the best in your endeavors.
                </p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                    <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                        Best regards,<br>
                        <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                    </p>
                </div>
            </div>
        </div>
        """
        
        plain_message = f"""
        Alumni Portal Application Update
        
        Hello {user_name},
        
        Thank you for your interest in joining our Alumni Portal community. 
        After careful review, we are unable to approve your application at this time.
        
        📝 What's Next? You may reapply in the future or contact our support team 
        if you believe this decision was made in error.
        
        We appreciate your understanding and wish you all the best in your endeavors.
        
        Best regards,
        The Alumni Portal Team
        """
        
        try:
            email_message = EmailMessage(
                subject=subject,
                body=plain_message,
                from_email=settings.EMAIL_HOST_USER,
                to=[pending.email],
            )
            email_message.attach_alternative(html_message, "text/html")
            email_message.send(fail_silently=False)
        except Exception:
            send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [pending.email], fail_silently=False)
        
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
    
    def post(self, request):
        """
        Send birthday notifications for specific users.
        
        Expected payload:
        {
            "user_ids": [1, 2, 3],  # Optional: specific user IDs
            "send_all_today": true,  # Optional: send for all today's birthdays
            "notify_upcoming": true  # Optional: notify for upcoming birthdays (3 days)
        }
        """
        from .tasks import send_birthday_notifications_to_batchmates
        
        user_ids = request.data.get('user_ids', [])
        send_all_today = request.data.get('send_all_today', False)
        notify_upcoming = request.data.get('notify_upcoming', False)
        
        notifications_triggered = 0
        errors = []
        
        # Handle specific user IDs
        if user_ids:
            for user_id in user_ids:
                try:
                    user = User.objects.get(id=user_id, date_of_birth__isnull=False)
                    # Calculate days until birthday
                    today = timezone.now().date()
                    birth_month = user.date_of_birth.month
                    birth_day = user.date_of_birth.day
                    
                    try:
                        next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
                    except ValueError:
                        if birth_month == 2 and birth_day == 29:
                            next_birthday = timezone.datetime(today.year, 2, 28).date()
                        else:
                            continue
                    
                    if next_birthday < today:
                        try:
                            next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                        except ValueError:
                            if birth_month == 2 and birth_day == 29:
                                next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                            else:
                                continue
                    
                    days_until = (next_birthday - today).days
                    send_birthday_notifications_to_batchmates.delay(user_id, days_until=days_until)
                    notifications_triggered += 1
                    
                except User.DoesNotExist:
                    errors.append(f"User with ID {user_id} not found")
                except Exception as e:
                    errors.append(f"Error processing user ID {user_id}: {str(e)}")
        
        # Handle all today's birthdays
        if send_all_today:
            today = timezone.now().date()
            today_birthday_users = []
            
            users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)
            for user in users_with_birthdays:
                birth_month = user.date_of_birth.month
                birth_day = user.date_of_birth.day
                
                try:
                    next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year, 2, 28).date()
                    else:
                        continue
                
                if next_birthday < today:
                    try:
                        next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                    except ValueError:
                        if birth_month == 2 and birth_day == 29:
                            next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                        else:
                            continue
                
                days_until_birthday = (next_birthday - today).days
                if days_until_birthday == 0:
                    today_birthday_users.append(user.id)
            
            for user_id in today_birthday_users:
                send_birthday_notifications_to_batchmates.delay(user_id, days_until=0)
                notifications_triggered += 1
        
        # Handle upcoming birthdays (3 days from now)
        if notify_upcoming:
            today = timezone.now().date()
            upcoming_birthday_users = []
            
            users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)
            for user in users_with_birthdays:
                birth_month = user.date_of_birth.month
                birth_day = user.date_of_birth.day
                
                try:
                    next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year, 2, 28).date()
                    else:
                        continue
                
                if next_birthday < today:
                    try:
                        next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                    except ValueError:
                        if birth_month == 2 and birth_day == 29:
                            next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                        else:
                            continue
                
                days_until_birthday = (next_birthday - today).days
                if days_until_birthday == 3:
                    upcoming_birthday_users.append(user.id)
            
            for user_id in upcoming_birthday_users:
                send_birthday_notifications_to_batchmates.delay(user_id, days_until=3)
                notifications_triggered += 1
        
        response_data = {
            'success': True,
            'notifications_triggered': notifications_triggered,
            'message': f'Triggered {notifications_triggered} birthday notification tasks'
        }
        
        if errors:
            response_data['errors'] = errors
            response_data['partial_success'] = True
        
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
            "email": User.objects.exclude(email__isnull=True).exclude(email="").values_list("email", flat=True).distinct().order_by("email"),
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
    """Enhanced filter set for alumni admin view with comprehensive filtering options."""
    
    # Text search filters
    username = django_filters.CharFilter(lookup_expr='icontains')
    email = django_filters.CharFilter(lookup_expr='icontains')
    first_name = django_filters.CharFilter(lookup_expr='icontains')
    last_name = django_filters.CharFilter(lookup_expr='icontains')
    phone = django_filters.CharFilter(lookup_expr='icontains')
    current_work = django_filters.CharFilter(lookup_expr='icontains')
    college_name = django_filters.CharFilter(lookup_expr='icontains')
    company = django_filters.CharFilter(lookup_expr='icontains')
    position = django_filters.CharFilter(lookup_expr='icontains')
    course = django_filters.CharFilter(lookup_expr='icontains')
    current_location = django_filters.CharFilter(lookup_expr='icontains')
    city = django_filters.CharFilter(lookup_expr='icontains')
    state = django_filters.CharFilter(lookup_expr='icontains')
    country = django_filters.CharFilter(lookup_expr='icontains')
    chapter = django_filters.CharFilter(lookup_expr='icontains')
    Address = django_filters.CharFilter(lookup_expr='icontains')
    
    # Exact match filters
    gender = django_filters.ChoiceFilter(choices=[
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ])
    role = django_filters.CharFilter(lookup_expr='iexact')
    zip_code = django_filters.CharFilter(lookup_expr='exact')
    
    # Numeric filters
    passed_out_year = django_filters.NumberFilter()
    passed_out_year_range = django_filters.RangeFilter(field_name='passed_out_year')
    course_end_year = django_filters.NumberFilter()
    course_end_year_range = django_filters.RangeFilter(field_name='course_end_year')
    
    # Date filters
    date_of_birth = django_filters.DateFilter()
    date_of_birth_range = django_filters.DateFromToRangeFilter(field_name='date_of_birth')
    date_joined = django_filters.DateFilter()
    date_joined_range = django_filters.DateFromToRangeFilter(field_name='date_joined')
    last_login = django_filters.DateFilter()
    last_login_range = django_filters.DateFromToRangeFilter(field_name='last_login')
    
    # Boolean filters
    is_active = django_filters.BooleanFilter()
    is_staff = django_filters.BooleanFilter()
    is_superuser = django_filters.BooleanFilter()
    
    # Custom method filters
    roles_played = django_filters.CharFilter(method='filter_roles_played')
    Worked_in = django_filters.CharFilter(method='filter_Worked_in')
    status = django_filters.ChoiceFilter(
        field_name='is_active',
        choices=[
            ('active', 'Active'),
            ('inactive', 'Inactive'),
            ('all', 'All'),
        ],
        method='filter_status'
    )
    
    # Search across multiple fields
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name', 'gender',
            'date_of_birth', 'current_work', 'college_name', 'chapter',
            'phone', 'city', 'state', 'country', 'zip_code', 'role',
            'course_end_year', 'company', 'position', 'course', 'passed_out_year', 
            'current_location', 'is_active', 'is_staff', 'is_superuser', 'Address'
        ]

    def filter_roles_played(self, queryset, name, value):
        """Filter by roles played field with partial matching."""
        if value:
            return queryset.filter(
                Q(roles_played__icontains=value) |
                Q(roles_played__startswith=value) |
                Q(roles_played__endswith=value)
            )
        return queryset

    def filter_Worked_in(self, queryset, name, value):
        """Filter by worked in field with partial matching."""
        if value:
            return queryset.filter(
                Q(Worked_in__icontains=value) |
                Q(Worked_in__startswith=value) |
                Q(Worked_in__endswith=value)
            )
        return queryset

    def filter_status(self, queryset, name, value):
        """Filter by user status (active/inactive)."""
        if value == 'active':
            return queryset.filter(is_active=True)
        elif value == 'inactive':
            return queryset.filter(is_active=False)
        return queryset

    def filter_search(self, queryset, name, value):
        """Global search across multiple fields."""
        if value:
            return queryset.filter(
                Q(username__icontains=value) |
                Q(email__icontains=value) |
                Q(first_name__icontains=value) |
                Q(last_name__icontains=value) |
                Q(phone__icontains=value) |
                Q(current_work__icontains=value) |
                Q(college_name__icontains=value) |
                Q(company__icontains=value) |
                Q(position__icontains=value) |
                Q(course__icontains=value) |
                Q(city__icontains=value) |
                Q(state__icontains=value) |
                Q(country__icontains=value) |
                Q(current_location__icontains=value)
            )
        return queryset

class AlumniAdminFilterView(ListAPIView):
    """
    Enhanced admin view for filtering alumni with user management capabilities.
    Supports filtering, search, ordering, pagination, and user status management.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = AlumniPagination
    filter_backends = [django_filters.rest_framework.DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AlumniAdminFilter

    search_fields = [
        'username', 'first_name', 'last_name'
    ]
    ordering_fields = '__all__'
    ordering = ['first_name', 'last_name']

    def get_queryset(self):
        """Get filtered queryset with proper ordering."""
        queryset = super().get_queryset().order_by('id')
        
        # Exclude current user from results if needed
        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            queryset = queryset.exclude(id=self.request.user.id)

        return queryset

    def list(self, request, *args, **kwargs):
        """Enhanced list method that includes user status information."""
        # Get the queryset and paginate
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            # Enhanced serialization with status information
            users_data = []
            for user in page:
                user_data = UserSerializer(user).data
                # Add status information
                user_data.update({
                    'approval_status': {
                        'is_active': user.is_active,
                        'is_staff': user.is_staff,
                        'is_superuser': user.is_superuser,
                        'status_display': 'Active' if user.is_active else 'Inactive',
                        'account_type': self._get_account_type(user),
                        'last_login': user.last_login,
                        'date_joined': user.date_joined
                    },
                    'management_actions': {
                        'can_deactivate': self._can_manage_user(request.user, user),
                        'can_delete': self._can_delete_user(request.user, user),
                        'can_reactivate': self._can_manage_user(request.user, user) and not user.is_active
                    }
                })
                users_data.append(user_data)
            
            return self.get_paginated_response(users_data)

        # Fallback without pagination
        users_data = []
        for user in queryset:
            user_data = UserSerializer(user).data
            user_data.update({
                'approval_status': {
                    'is_active': user.is_active,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                    'status_display': 'Active' if user.is_active else 'Inactive',
                    'account_type': self._get_account_type(user),
                    'last_login': user.last_login,
                    'date_joined': user.date_joined
                },
                'management_actions': {
                    'can_deactivate': self._can_manage_user(request.user, user),
                    'can_delete': self._can_delete_user(request.user, user),
                    'can_reactivate': self._can_manage_user(request.user, user) and not user.is_active
                }
            })
            users_data.append(user_data)
        
        return Response(users_data)

    def _get_account_type(self, user):
        """Determine the account type based on user attributes."""
        if user.is_superuser:
            return 'Super Admin'
        elif user.is_staff:
            return 'Staff'
        elif user.role:
            return user.role
        else:
            return 'Alumni'

    def _can_manage_user(self, requesting_user, target_user):
        """Check if the requesting user can manage the target user."""
        # Superusers can manage anyone except other superusers
        if requesting_user.is_superuser:
            return not target_user.is_superuser or requesting_user.id == target_user.id
        
        # Staff/Admin can manage regular users but not staff/admin/superusers
        if requesting_user.role in ["Admin", "Staff"]:
            return not (target_user.is_staff or target_user.is_superuser or target_user.role in ["Admin", "Staff"])
        
        return False

    def _can_delete_user(self, requesting_user, target_user):
        """Check if the requesting user can delete the target user."""
        # Only superusers can delete users, and they cannot delete other superusers
        if requesting_user.is_superuser:
            return not target_user.is_superuser
        
        return False

    def post(self, request, *args, **kwargs):
        """Handle user management actions (deactivate, reactivate)."""
        action = request.data.get('action')
        user_ids = request.data.get('user_ids', [])
        user_id = request.data.get('user_id')
        reason = request.data.get('reason', 'Action performed by administrator')
        notify_user = request.data.get('notify_user', True)

        # Check permissions
        if not (request.user.is_superuser or request.user.role in ["Admin", "Staff"]):
            return Response(
                {"error": "Permission denied. Admin or Staff access required."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Handle single user action
        if user_id:
            user_ids = [user_id]

        if not user_ids:
            return Response(
                {"error": "user_id or user_ids required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        valid_actions = ['deactivate', 'activate', 'delete']
        if action not in valid_actions:
            return Response(
                {"error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        successful_operations = []
        failed_operations = []

        for uid in user_ids:
            try:
                target_user = User.objects.get(id=uid)
                
                # Permission checks
                if action == 'delete':
                    if not self._can_delete_user(request.user, target_user):
                        failed_operations.append({
                            'user_id': uid,
                            'error': 'Permission denied to delete this user'
                        })
                        continue
                else:
                    if not self._can_manage_user(request.user, target_user):
                        failed_operations.append({
                            'user_id': uid,
                            'error': 'Permission denied to manage this user'
                        })
                        continue

                # Prevent self-modification
                if target_user.id == request.user.id:
                    failed_operations.append({
                        'user_id': uid,
                        'error': 'Cannot perform action on your own account'
                    })
                    continue

                # Perform the action
                if action == 'delete':
                    # Store user info before deletion
                    user_info = {
                        'user_id': target_user.id,
                        'username': target_user.username,
                        'email': target_user.email,
                        'name': f"{target_user.first_name} {target_user.last_name}".strip()
                    }
                    
                    # Send notification before deletion if requested
                    if notify_user and target_user.email:
                        try:
                            user_name = target_user.first_name or target_user.username
                            send_notification_email(
                                target_user.email,
                                "⚠️ Alumni Portal - Account Deletion Notice",
                                "Account Deletion Notice ⚠️",
                                f"""
                                <p>Dear {user_name}, 👋</p>
                                
                                <p>We're writing to inform you that your Alumni Portal account has been permanently deleted by our administrator.</p>
                                
                                <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                                    <p style="color: #856404; margin: 0;"><strong>Reason:</strong> {reason}</p>
                                </div>
                                
                                <p>If you believe this action was taken in error, please contact our support team immediately. We're here to help resolve any concerns you may have.</p>
                                
                                <p>Thank you for being part of our community. We wish you all the best in your future endeavors.</p>
                                """
                            )
                        except Exception:
                            pass
                    
                    # Delete the user
                    target_user.delete()
                    
                    successful_operations.append({
                        **user_info,
                        'action': 'deleted',
                        'timestamp': timezone.now().isoformat()
                    })

                elif action == 'deactivate':
                    if not target_user.is_active:
                        failed_operations.append({
                            'user_id': uid,
                            'error': 'User is already inactive'
                        })
                        continue

                    target_user.is_active = False
                    target_user.save(update_fields=['is_active'])

                    # Delete auth token to force logout
                    try:
                        target_user.auth_token.delete()
                    except:
                        pass

                    # Send notification
                    if notify_user and target_user.email:
                        try:
                            user_name = target_user.first_name or target_user.username
                            send_notification_email(
                                target_user.email,
                                "🔒 Alumni Portal - Account Deactivated",
                                "Account Temporarily Deactivated 🔒",
                                f"""
                                <p>Dear {user_name}, 👋</p>
                                
                                <p>We're writing to inform you that your Alumni Portal account has been temporarily deactivated by our administrator.</p>
                                
                                <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
                                    <p style="color: #856404; margin: 0;"><strong>Reason:</strong> {reason}</p>
                                </div>
                                
                                <p>Your account access has been suspended, but your data remains safe. If you believe this action was taken in error or would like to discuss reactivation, please contact our support team.</p>
                                
                                <p>We appreciate your understanding and look forward to resolving this matter promptly.</p>
                                """
                            )
                        except Exception:
                            pass

                    successful_operations.append({
                        'user_id': target_user.id,
                        'username': target_user.username,
                        'email': target_user.email,
                        'name': f"{target_user.first_name} {target_user.last_name}".strip(),
                        'action': 'deactivated',
                        'previous_status': True,
                        'new_status': False,
                        'timestamp': timezone.now().isoformat()
                    })

                elif action == 'activate':
                    if target_user.is_active:
                        failed_operations.append({
                            'user_id': uid,
                            'error': 'User is already active'
                        })
                        continue

                    target_user.is_active = True
                    target_user.save(update_fields=['is_active'])

                    # Send notification
                    if notify_user and target_user.email:
                        try:
                            user_name = target_user.first_name or target_user.username
                            login_url = "https://karpagamalumni.in/login/"
                            send_notification_email(
                                target_user.email,
                                "✅ Alumni Portal - Account Reactivated",
                                "Welcome Back! Account Reactivated ✅",
                                f"""
                                <p>Dear {user_name}, 👋</p>
                                
                                <p>Great news! Your Alumni Portal account has been reactivated by our administrator. Welcome back to our community! 🎉</p>
                                
                                <div style="background-color: #d5f4e6; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #27ae60;">
                                    <p style="color: #27ae60; margin: 0;"><strong>🚀 You can now:</strong></p>
                                    <p style="color: #2c3e50; margin: 5px 0 0 0;">Access all features of the Alumni Portal and reconnect with your network!</p>
                                </div>
                                
                                <p>You can log in immediately and continue where you left off. Thank you for your patience during the temporary suspension.</p>
                                
                                <p>We're excited to have you back in our alumni community! 🌟</p>
                                """,
                                "🎯 Login Now",
                                login_url
                            )
                        except Exception:
                            pass

                    successful_operations.append({
                        'user_id': target_user.id,
                        'username': target_user.username,
                        'email': target_user.email,
                        'name': f"{target_user.first_name} {target_user.last_name}".strip(),
                        'action': 'activated',
                        'previous_status': False,
                        'new_status': True,
                        'timestamp': timezone.now().isoformat()
                    })

            except User.DoesNotExist:
                failed_operations.append({
                    'user_id': uid,
                    'error': 'User not found'
                })
            except Exception as e:
                failed_operations.append({
                    'user_id': uid,
                    'error': str(e)
                })

        # Log the action
        try:
            LoginLog.objects.create(
                user=request.user,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                timestamp=timezone.now()
            )
        except:
            pass

        return Response({
            "message": f"User management operation completed",
            "action": action,
            "summary": {
                "total_requested": len(user_ids),
                "successful": len(successful_operations),
                "failed": len(failed_operations)
            },
            "successful_operations": successful_operations,
            "failed_operations": failed_operations,
            "performed_by": request.user.username,
            "timestamp": timezone.now().isoformat()
        }, status=status.HTTP_200_OK)


#####################################
#           EVENT VIEWS             #
#####################################

class EventView(BaseMultiPartView):
    """View for listing and creating events."""
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


class EventDetailView(BaseMultiPartView, BaseObjectRetrievalMixin):
    """View for retrieving, updating, and deleting a specific event."""
    
    def get_object(self, pk):
        """Get an event by primary key or raise 404."""
        return self.get_object_or_404(Events, pk=pk)
            
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

class JobListCreateView(BaseMultiPartView):
    """View for listing and creating jobs."""
    permission_classes = [permissions.AllowAny]
    
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
        thirty_days_ago = now - timedelta(days=30)
        
        # Use select_related and prefetch_related for optimized queries
        # Upcoming Events
        upcoming_events = Events.objects.select_related('user').all().order_by('from_date_time')[:3]
        events_serializer = EventSerializer(upcoming_events, many=True)
        
        # Latest Album Images with user data
        latest_album_images = Album.objects.select_related('user').all().order_by('-id')[:5]
        album_images_serializer = AlbumSerializer(latest_album_images, many=True)
        
        # Latest Members with photos
        users_with_photos = User.objects.filter(
            profile_photo__isnull=False
        ).exclude(profile_photo='').order_by('-id')[:3]
        members_serializer = UserSerializer(users_with_photos, many=True)
        
        # Batch Mates - Get users from same passed_out_year as current user
        batch_mates_data = []
        if request.user.is_authenticated and request.user.passed_out_year:
            batch_mates = User.objects.filter(
                passed_out_year=request.user.passed_out_year
            ).exclude(id=request.user.id).order_by('first_name')[:10]
            batch_mates_serializer = UserSerializer(batch_mates, many=True)
            batch_mates_data = batch_mates_serializer.data
            
        # Chapters - Get all unique chapters and count of users in each
        chapters = User.objects.exclude(chapter='').values('chapter').annotate(
            member_count=Count('id')
        ).order_by('-member_count')
        
        # Featured news with user data
        featured_news = NewsRoom.objects.select_related('user').all().order_by('-published_on')[:3]
        news_serializer = NewsRoomSerializer(featured_news, many=True)
        
        # Statistics - optimized with single queries
        stats_data = {
            'total_users': User.objects.count() + PendingSignup.objects.count(),
            'new_users': User.objects.filter(date_joined__gte=thirty_days_ago).count(),
            'upcoming_events': Events.objects.filter(from_date_time__gte=now).count(),
            'albums_count': Album.objects.count(),
        }
        
        # Compile and return response
        return Response({
            'upcoming_events': events_serializer.data,
            'latest_album_images': album_images_serializer.data,
            'latest_members': members_serializer.data,
            'batch_mates': batch_mates_data,
            'chapters': list(chapters),
            'featured_news': news_serializer.data,
            **stats_data,
        }, status=status.HTTP_200_OK)


class MyPostsView(BaseAuthenticatedView):
    """View for listing the current user's posts."""
    
    def get(self, request):
        """Get all jobs, events, and news created by the authenticated user."""
        # Use select_related for optimized queries
        jobs = Jobs.objects.filter(user=request.user).order_by('-posted_on')
        jobs_serializer = JobsSerializer(jobs, many=True)
        
        events = Events.objects.filter(user=request.user).order_by('-uploaded_on')
        events_serializer = EventSerializer(events, many=True)

        news = NewsRoom.objects.filter(user=request.user).order_by('-published_on')
        news_serializer = NewsRoomSerializer(news, many=True)
        
        return Response({
            "jobs": jobs_serializer.data,
            "events": events_serializer.data,
            "news": news_serializer.data,
        }, status=status.HTTP_200_OK)


class ImportMembersAPIView(APIView):
    """View for importing members from a CSV file."""
    
    def _process_boolean_field(self, value):
        """Convert string values to proper boolean values."""
        if isinstance(value, str):
            value = value.strip().lower()
            if value in ('', 'none', 'null', 'false', '0', 'no'):
                return False
            elif value in ('true', '1', 'yes', 'on'):
                return True
        return bool(value) if value else False
    
    def post(self, request):
        """
        Import registered members from members.csv into the CustomUser model.
        
        Uses email as username and date of birth as password. Maps all available 
        fields from the CSV to the CustomUser model.
        
        Returns:
            Statistics about the import operation
        """
        csv_path = os.path.join(settings.BASE_DIR, 'members.csv')
        created, updated, skipped = [], [], []
        
        if not os.path.exists(csv_path):
            return Response(
                {"error": "CSV file not found"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with open(csv_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row_num, row in enumerate(reader, start=2):  # Start at 2 for header
                    # Extract core data
                    email = row.get('email_id', '').strip().lower()
                    if not email:
                        skipped.append(f"Row {row_num}: No email provided")
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
                    
                    # Handle boolean fields to prevent ValidationError
                    boolean_fields = ['is_active', 'is_staff', 'is_superuser', 'is_entrepreneur']
                    for field in boolean_fields:
                        csv_value = row.get(field, '')
                        user_data[field] = self._process_boolean_field(csv_value)
                    
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
                    else:
                        # Ensure is_staff is explicitly set to False if not faculty
                        user_data.setdefault('is_staff', False)

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
                        # Create new user with proper boolean values
                        user = User(**user_data)
                        user.set_password(password)
                        user.save()
                        created.append(email)
                    except Exception as e:
                        skipped.append(f"Row {row_num} - {email}: {str(e)}")

        except FileNotFoundError:
            return Response(
                {"error": "CSV file not found"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": f"Error processing CSV: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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
            
            # Mark user as entrepreneur when they create a business listing, except for admins
            if not request.user.is_entrepreneur and not request.user.is_superuser:
                request.user.is_entrepreneur = True
                request.user.save(update_fields=['is_entrepreneur'])
            
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
        if news_article.user == request.user or request.user.role not in ["Staff", "Admin"]:
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
        # if news_article.user != request.user or request.user.role not in ["Staff", "Admin"]:
        #     return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
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

class ProfileCompletionInsightsView(APIView):
    """View for providing comprehensive profile completion insights."""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get detailed profile completion insights for the authenticated user.
        
        Returns:
            - Overall completion percentage
            - Section-wise completion details
            - Missing fields with suggestions
            - Completion score breakdown
            - Recommendations for improvement
        """
        user = request.user
        
        # Define profile sections with their fields and weights
        profile_sections = {
            'basic_info': {
            'weight': 25,
            'fields': {
                'first_name': {'required': True, 'weight': 15},
                'last_name': {'required': True, 'weight': 15},
                'email': {'required': True, 'weight': 10},
                'phone': {'required': True, 'weight': 15},
                'gender': {'required': False, 'weight': 10},
                'date_of_birth': {'required': False, 'weight': 15},
                'bio': {'required': False, 'weight': 10},
                'profile_photo': {'required': False, 'weight': 10}
            }
            },
            'education': {
            'weight': 20,
            'fields': {
                'college_name': {'required': True, 'weight': 25},
                'course': {'required': True, 'weight': 20},
                'passed_out_year': {'required': True, 'weight': 20},
                'roll_no': {'required': False, 'weight': 10},
                'course_start_year': {'required': False, 'weight': 5},
                'course_end_year': {'required': False, 'weight': 5}
            }
            },
            'professional': {
            'weight': 25,
            'fields': {
                'current_work': {'required': True, 'weight': 20},
                'company': {'required': False, 'weight': 15},
            }
            },
            'contact_location': {
            'weight': 15,
            'fields': {
                'city': {'required': True, 'weight': 25},
                'state': {'required': True, 'weight': 20},
                'country': {'required': True, 'weight': 20},
                'Address': {'required': False, 'weight': 15},
                'zip_code': {'required': False, 'weight': 10},
                'current_location': {'required': False, 'weight': 10}
            }
            },
            'social_media': {
            'weight': 10,
            'fields': {
                'linkedin_link': {'required': False, 'weight': 40},
                'facebook_link': {'required': False, 'weight': 20},
                'twitter_link': {'required': False, 'weight': 20},
                'website_link': {'required': False, 'weight': 20}
            }
            },
            'additional': {
            'weight': 5,
            'fields': {
                'chapter': {'required': False, 'weight': 30},
            }
            }
        }
        
        # Calculate completion for each section
        section_insights = {}
        overall_weighted_score = 0
        total_possible_score = 0
        missing_critical_fields = []
        recommendations = []
        
        for section_name, section_data in profile_sections.items():
            section_weight = section_data['weight']
            section_fields = section_data['fields']
            
            section_score = 0
            section_max_score = 0
            completed_fields = []
            missing_fields = []
            missing_required_fields = []
            
            for field_name, field_config in section_fields.items():
                field_weight = field_config['weight']
                is_required = field_config['required']
                section_max_score += field_weight
                
                # Get field value
                field_value = getattr(user, field_name, None)
                
                # Check if field is completed
                is_completed = False
                if field_value is not None:
                    if isinstance(field_value, str):
                        is_completed = bool(field_value.strip())
                    elif isinstance(field_value, list):
                        is_completed = bool(field_value)
                    elif hasattr(field_value, 'url'):  # File fields
                        is_completed = bool(field_value)
                    else:
                        is_completed = bool(field_value)
                
                if is_completed:
                    section_score += field_weight
                    completed_fields.append({
                        'field': field_name,
                        'weight': field_weight,
                        'required': is_required
                    })
                else:
                    missing_fields.append({
                        'field': field_name,
                        'weight': field_weight,
                        'required': is_required
                    })
                    if is_required:
                        missing_required_fields.append(field_name)
                        missing_critical_fields.append({
                            'field': field_name,
                            'section': section_name,
                            'impact': 'high' if field_weight >= 15 else 'medium'
                        })
            
            # Calculate section completion percentage
            section_completion = (section_score / section_max_score * 100) if section_max_score > 0 else 0
            
            # Add to overall weighted score
            section_weighted_score = (section_completion / 100) * section_weight
            overall_weighted_score += section_weighted_score
            total_possible_score += section_weight
            
            section_insights[section_name] = {
                'completion_percentage': round(section_completion, 1),
                'score': section_score,
                'max_score': section_max_score,
                'weight': section_weight,
                'weighted_score': round(section_weighted_score, 1),
                'completed_fields': completed_fields,
                'missing_fields': missing_fields,
                'missing_required_count': len(missing_required_fields),
                'status': 'complete' if section_completion == 100 else 'incomplete'
            }
        
        # Calculate overall completion percentage
        overall_completion = (overall_weighted_score / total_possible_score * 100) if total_possible_score > 0 else 0
        
        # Generate recommendations
        if overall_completion < 50:
            recommendations.append("Focus on completing basic information and education details first")
        if section_insights['basic_info']['completion_percentage'] < 80:
            recommendations.append("Complete your basic profile information to make a better first impression")
        if section_insights['professional']['completion_percentage'] < 60:
            recommendations.append("Add your professional experience and skills to showcase your career")
        if not getattr(user, 'profile_photo', None):
            recommendations.append("Upload a profile photo to increase profile visibility by 40%")
        if not getattr(user, 'linkedin_link', None):
            recommendations.append("Add your LinkedIn profile to enhance professional networking")
        if section_insights['contact_location']['completion_percentage'] < 70:
            recommendations.append("Complete your location details to connect with nearby alumni")
        
        # Profile strength assessment
        if overall_completion >= 90:
            profile_strength = "Excellent"
            strength_message = "Your profile is comprehensive and will attract great connections!"
        elif overall_completion >= 75:
            profile_strength = "Good"
            strength_message = "Your profile is well-developed. Consider adding more details for better visibility."
        elif overall_completion >= 50:
            profile_strength = "Fair"
            strength_message = "Your profile has good basics. Add more information to stand out."
        else:
            profile_strength = "Needs Improvement"
            strength_message = "Complete your profile to unlock networking opportunities."
        
        # Calculate profile completeness level
        completed_sections = sum(1 for section in section_insights.values() if section['completion_percentage'] == 100)
        total_sections = len(section_insights)
        
        # Activity suggestions based on completion
        next_steps = []
        if overall_completion < 100:
            # Find the section with lowest completion that has required fields
            lowest_section = min(
                section_insights.items(),
                key=lambda x: x[1]['completion_percentage']
            )
            next_steps.append(f"Focus on completing your {lowest_section[0].replace('_', ' ').title()} section")
        
        if len(missing_critical_fields) > 0:
            next_steps.append("Fill in required fields to boost your profile score significantly")
        
        response_data = {
            'user_info': {
                'username': user.username,
                'name': f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}".strip(),
                'profile_updated_on': getattr(user, 'profile_updated_on', None)
            },
            'overall_completion': {
                'percentage': round(overall_completion, 1),
                'strength': profile_strength,
                'message': strength_message,
                'completed_sections': completed_sections,
                'total_sections': total_sections
            },
            'section_details': section_insights,
            'critical_missing': {
                'count': len(missing_critical_fields),
                'fields': missing_critical_fields
            },
            'recommendations': recommendations,
            'next_steps': next_steps,
            'profile_stats': {
                'total_fields_available': sum(len(section['fields']) for section in profile_sections.values()),
                'completed_fields': sum(len(section['completed_fields']) for section in section_insights.values()),
                'missing_required_fields': len(missing_critical_fields),
                'has_profile_photo': bool(getattr(user, 'profile_photo', None)),
                'has_cover_photo': bool(getattr(user, 'cover_photo', None)),
                'social_links_count': sum(1 for link in ['linkedin_link', 'facebook_link', 'twitter_link', 'website_link'] 
                                        if getattr(user, link, None))
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)


import pandas as pd
from datetime import datetime
from django.utils import timezone
from .models import CustomUser

def map_and_save_users(csv_path):
    """
    Enhanced function to map CSV data to CustomUser model with comprehensive field mapping
    """
    # Load CSV data
    try:
        data = pd.read_csv(csv_path)
        print(f"📊 Loaded CSV with {len(data)} rows")
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return

    success_count = 0
    error_count = 0
    
    for index, row in data.iterrows():
        try:
            # Step 1: Clean and prepare email (primary key)
            email = str(row.get("email", "")).strip().lower()
            if not email or email in ["nan", "null", ""]:
                print(f"⚠️ Row {index + 2}: No email provided, skipping")
                error_count += 1
                continue

            # Step 2: Process Date of Birth and generate password
            dob_str = str(row.get("date_of_birth", "")).strip()
            dob = None
            password = "defaultpassword"  # Default password

            if dob_str and dob_str.lower() not in ["", "nan", "null"]:
                try:
                    # Try multiple date formats
                    for date_format in ["%d-%m-%Y", "%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y"]:
                        try:
                            dob = datetime.strptime(dob_str, date_format).date()
                            password = dob.strftime("%d%m%Y")  # Convert to DDMMYYYY
                            break
                        except ValueError:
                            continue
                    
                    if not dob:
                        # Try pandas to_datetime as fallback
                        dob = pd.to_datetime(dob_str, errors='coerce')
                        if pd.notna(dob):
                            dob = dob.date()
                            password = dob.strftime("%d%m%Y")
                            
                except Exception as e:
                    print(f"⚠️ Row {index + 2}: Invalid DOB format '{dob_str}', using default password. Error: {e}")

            # Step 3: Clean and prepare basic fields with proper null handling
            def clean_field(value, default=""):
                """Helper function to clean field values"""
                if pd.isna(value) or str(value).strip().lower() in ["nan", "null", ""]:
                    return default
                return str(value).strip()

            def clean_year_field(value, default=""):
                """Helper function specifically for year fields to handle .0 issue"""
                if pd.isna(value) or str(value).strip().lower() in ["nan", "null", ""]:
                    return default
                
                # Convert to string and remove .0 if present
                year_str = str(value).strip()
                if year_str.endswith('.0'):
                    year_str = year_str[:-2]
                
                # Validate it's a reasonable year
                try:
                    year_int = int(float(year_str))
                    if 1900 <= year_int <= 2030:  # Reasonable year range
                        return str(year_int)
                    else:
                        return default
                except (ValueError, TypeError):
                    return default

            def clean_numeric_field(value, default=0):
                """Helper function to clean numeric fields - return 0 instead of None for non-nullable fields"""
                if pd.isna(value) or str(value).strip().lower() in ["nan", "null", ""]:
                    return default
                try:
                    return int(float(str(value)))
                except (ValueError, TypeError):
                    return default

            def clean_float_field(value, default=0.0):
                """Helper function to clean float fields"""
                if pd.isna(value) or str(value).strip().lower() in ["nan", "null", ""]:
                    return default
                try:
                    return float(str(value))
                except (ValueError, TypeError):
                    return default

            def clean_boolean_field(value, default=False):
                """Helper function to clean boolean fields"""
                if pd.isna(value):
                    return default
                str_val = str(value).strip().lower()
                if str_val in ["true", "1", "yes", "on", "staff", "admin"]:
                    return True
                elif str_val in ["false", "0", "no", "off", "alumni", ""]:
                    return False
                return default

            # Step 4: Map all CSV fields to model fields
            name_parts = clean_field(row.get("name", "")).split(" ", 1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            # Determine role and permissions
            role = clean_field(row.get("role", "Alumni"))
            label = clean_field(row.get("label", ""))
            
            # Set staff and superuser based on role and label
            is_staff = role.lower() in ["staff", "admin"] or "staff" in label.lower() or "professor" in label.lower()
            is_superuser = role.lower() == "admin"
            
            # If no explicit role but has staff indicators in label, set as Staff
            if role.lower() == "alumni" and ("professor" in label.lower() or "assistant" in label.lower() or "associate" in label.lower()):
                role = "Staff"
                is_staff = True

            # Step 5: Prepare comprehensive user data with proper null handling
            user_data = {
                # Basic authentication fields
                "username": email,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "is_active": True,
                "is_staff": is_staff,
                "is_superuser": is_superuser,
                
                # Personal information
                "salutation": clean_field(row.get("salutation")),
                "name": clean_field(row.get("name", "")),
                "gender": clean_field(row.get("gender", "")),
                "date_of_birth": dob,
                "label": label,
                "role": role,
                
                # Contact information
                "phone": clean_field(row.get("Mobile Phone No.", "")),
                "office_phone_no": clean_field(row.get("Office Phone No.", "")),
                "home_phone_no": clean_field(row.get("Home Phone No.", "")),
                "secondary_email": clean_field(row.get("secondary_email", "")),
                
                # Address information
                "Address": clean_field(row.get("Address", "")),
                "city": clean_field(row.get("city", "")),
                "state": clean_field(row.get("state", "")),
                "country": clean_field(row.get("country", "")),
                "zip_code": clean_field(row.get("zip_code", "")),
                "current_location": clean_field(row.get("current_location", "")),
                "home_town": clean_field(row.get("home_town", "")),
                
                # Correspondence address
                "correspondence_address": clean_field(row.get("correspondence_address", "")),
                "correspondence_city": clean_field(row.get("correspondence_city", "")),
                "correspondence_state": clean_field(row.get("correspondence_state", "")),
                "correspondence_country": clean_field(row.get("correspondence_country", "")),
                "correspondence_pincode": clean_field(row.get("correspondence_pincode", "")),
                
                # Educational information - handle CharField fields properly with year cleaning
                "college_name": clean_field(row.get("college_name", "")),
                "course": clean_field(row.get("course", "")),
                "stream": clean_field(row.get("stream", "")),
                "passed_out_year": clean_year_field(row.get("passed_out_year", "")),  # Use clean_year_field
                "course_start_year": clean_year_field(row.get("course_start_year", "")),  # Use clean_year_field
                "course_end_year": clean_year_field(row.get("course_end_year", "")),  # Use clean_year_field
                "roll_no": clean_field(row.get("roll_no", "")),
                "branch": clean_field(row.get("branch", "")),
                
                # Professional information
                "current_work": clean_field(row.get("current_work", "")),
                "company": clean_field(row.get("company", "")),
                "position": clean_field(row.get("position", "")),
                "work_experience": clean_float_field(row.get("work_experience"), 0.0),
                
                # Faculty specific fields with year cleaning
                "faculty_job_title": clean_field(row.get("faculty_job_title", "")),
                "faculty_institute": clean_field(row.get("faculty_institute", "")),
                "faculty_department": clean_field(row.get("faculty_department", "")),
                "faculty_start_year": clean_year_field(row.get("faculty_start_year", "")),  # Use clean_year_field
                "faculty_start_month": clean_field(row.get("faculty_start_month", "")),
                "faculty_end_year": clean_year_field(row.get("faculty_end_year", "")),  # Use clean_year_field
                "faculty_end_month": clean_field(row.get("faculty_end_month", "")),
                
                # Social links
                "facebook_link": clean_field(row.get("facebook_link", "")),
                "linkedin_link": clean_field(row.get("linkedin_link", "")),
                "website_link": clean_field(row.get("website_link", "")),
                "twitter_link": clean_field(row.get("twitter_link", "")),
                
                # Additional fields with year cleaning
                "chapter": clean_field(row.get("chapter", "")),
                "member_roles": clean_field(row.get("member_roles", "")),
                "educational_course": clean_field(row.get("educational_course", "")),
                "educational_institute": clean_field(row.get("educational_institute", "")),
                "start_year": clean_year_field(row.get("start_year", "")),  # Use clean_year_field
                "end_year": clean_year_field(row.get("end_year", "")),  # Use clean_year_field
                
                # Boolean flags
                "is_entrepreneur": clean_boolean_field(row.get("is_entrepreneur", False)),
                
                # Status fields - using CharField, so empty string
                "registered": clean_field(row.get("registered", "")),
                "registered_on": clean_field(row.get("registered_on", "")),
                "approved_on": clean_field(row.get("approved_on", "")),
                "profile_updated_on": clean_field(row.get("profile_updated_on", "")),
                "admin_note": clean_field(row.get("admin_note", "")),
                "profile_type": clean_field(row.get("profile_type", "")),
                "bio": clean_field(row.get("bio", "")),
            }

            # Handle JSON fields (arrays) with proper list handling
            for json_field, csv_field in [
                ('professional_skills', 'professional_skills'),
                ('industries_worked_in', 'industries_worked_in'),
                ('roles_played', 'roles_played'),
                ('Worked_in', 'worked_in'),
                ('experience', 'experience')
            ]:
                field_value = clean_field(row.get(csv_field, ""))
                if field_value:
                    # Split by comma and clean each item
                    user_data[json_field] = [item.strip() for item in field_value.split(',') if item.strip()]
                else:
                    user_data[json_field] = []

            # Handle social_links as JSON
            social_links = {}
            if clean_field(row.get("facebook_link", "")):
                social_links["Facebook"] = clean_field(row.get("facebook_link", ""))
            if clean_field(row.get("linkedin_link", "")):
                social_links["LinkedIn"] = clean_field(row.get("linkedin_link", ""))
            if clean_field(row.get("twitter_link", "")):
                social_links["Twitter"] = clean_field(row.get("twitter_link", ""))
            if clean_field(row.get("website_link", "")):
                social_links["Website"] = clean_field(row.get("website_link", ""))
            
            user_data['social_links'] = social_links

            # Step 6: Create or update user
            user, created = CustomUser.objects.update_or_create(
                email=email,  # Use email as the unique identifier
                defaults=user_data
            )

            if created:
                user.set_password(password)
                user.save()
                print(f"✅ [CREATED] {email} | Name: {first_name} {last_name} | Role: {role} | Password: {password}")
                success_count += 1
            else:
                # Update password only if it's different
                if not user.check_password(password):
                    user.set_password(password)
                    user.save()
                print(f"🔄 [UPDATED] {email} | Name: {first_name} {last_name} | Role: {role}")
                success_count += 1

        except Exception as e:
            print(f"❌ [ERROR] Row {index + 2} - {row.get('email', 'Unknown')}: {str(e)}")
            error_count += 1
            continue

    # Final summary
    print(f"\n📊 IMPORT SUMMARY:")
    print(f"✅ Successfully processed: {success_count} users")
    print(f"❌ Errors encountered: {error_count} users")
    print(f"📈 Total rows processed: {success_count + error_count}")
    print("🎉 Data mapping and saving completed!")


# csv_path = "api/registered_users_with_roles.csv"
# map_and_save_users(csv_path)