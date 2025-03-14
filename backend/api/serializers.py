# Serializer for Profile details
from . import models
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Jobs, JobComment

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = write_only=True
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']  

class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Profile
        fields = '__all__'

class LoginLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.LoginLog
        fields = ['timestamp', 'ip_address', 'browser', 'browser_version', 'device', 'successful']

class memberSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Profile
        fields = ['user', 'first_name', 'last_name', 'email', 'contact_number', 'passed_out_year', 'current_work', 'experience', 'social_links', 'profile_photo', 'cover_photo', 'bio']


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Events
        fields = '__all__'

    def create(self, validated_data):
        return super().create(validated_data)


class JobImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.JobImage
        fields = ['id', 'image']

class AlbumSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Album
        fields = ['id', 'title', 'description', 'cover_image', 'posted_on']

class AlbumImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.AlbumImage
        fields = ['id', 'image', 'album']

class JobCommentSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()  # Changed field to return user details

    class Meta:
        model = JobComment
        fields = ['id', 'job', 'user', 'comment', 'created_at']
        read_only_fields = ['id', 'created_at', 'job', 'user']

    def get_user(self, obj):
        profile = getattr(obj.user, 'profile', None)
        if profile:
            return {
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "user": profile.user.username,
                "profile_photo": profile.profile_photo.url if profile.profile_photo else ""
            }

class JobsSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()  # Changed field: return profile info
    images = JobImageSerializer(many=True, read_only=True)  # New field to send job images
    comments = JobCommentSerializer(many=True, read_only=True)
    total_comments = serializers.SerializerMethodField()
    total_reactions = serializers.SerializerMethodField()

    class Meta:
        model = Jobs
        fields = '__all__'
        extra_kwargs = {'user': {'read_only': True}}
        read_only_fields = ['id', 'posted_on', 'views', 'comments', 'images', 'total_reactions', 'total_comments']

    def get_user(self, obj):
        # Return first_name and last_name from the Profile model
        profile = getattr(obj.user, 'profile', None)
        if profile:
            return {
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "profile_photo": profile.profile_photo.url if profile.profile_photo else ""
            }
        return {}

    def get_total_reactions(self, obj):
        return sum(obj.reaction.values()) if obj.reaction else 0

    def get_total_comments(self, obj):
        return obj.comments.count()