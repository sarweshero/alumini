# Serializer for Profile details
from . import models
from rest_framework import serializers
from django.contrib.auth import get_user_model
from . import models

User = get_user_model()    
class PendingSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.PendingSignup
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'college_name', 'role', 'phone', 'social_links', 'profile_photo', 'cover_photo', 'bio', 'contact_number', 'passed_out_year', 'current_work', 'previous_work', 'experience']
        extra_kwargs = {'password': {'write_only': True}}

class LoginLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.LoginLog
        fields = ['timestamp', 'ip_address', 'browser', 'browser_version', 'device', 'successful']
class memberSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = [
            'username', 'first_name', 'last_name', 'email', 'contact_number', 
            'passed_out_year', 'current_work', 'experience', 'social_links', 
            'profile_photo', 'cover_photo', 'bio'
        ]

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
        model = models.JobComment
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
    user = serializers.SerializerMethodField() # Changed field: return profile info
    images = JobImageSerializer(many=True, read_only=True)
    comments = JobCommentSerializer(many=True, read_only=True)
    total_comments = serializers.SerializerMethodField()
    total_reactions = serializers.SerializerMethodField()

    class Meta:
        model = models.Jobs
        fields = '__all__'
        extra_kwargs = {
            'user': {'read_only': True},
            'role': {'read_only': True},
        }
        read_only_fields = ['id', 'posted_on', 'views', 'comments', 'images', 'total_reactions', 'total_comments']

    def get_user(self, obj):
        user = obj.user  # Directly use the custom user instance
        return {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "profile_photo": user.profile_photo.url if user.profile_photo else ""
        }

    def get_total_reactions(self, obj):
        return sum(obj.reaction.values()) if obj.reaction else 0

    def get_total_comments(self, obj):
        return obj.comments.count()

class UserLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.user_location
        fields = ['id', 'user', 'latitude', 'longitude']
        read_only_fields = ['id', 'user']

    def create(self, validated_data):
        request = self.context.get('request')
        if request:
            user = request.user
            try:
                instance = models.user_location.objects.get(user=user)
                instance.latitude = validated_data.get('latitude', instance.latitude)
                instance.longitude = validated_data.get('longitude', instance.longitude)
                instance.save()
                return instance
            except models.user_location.DoesNotExist:
                return models.user_location.objects.create(user=user, **validated_data)
        return super().create(validated_data)