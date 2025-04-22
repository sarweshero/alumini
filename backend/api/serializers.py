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
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'salutation', 'name', 'gender', 'date_of_birth', 'label', 'secondary_email',
            'profile_type', 'roll_no', 'course', 'stream',
            'course_start_year', 'course_end_year', 'faculty_job_title',
            'faculty_institute', 'faculty_department', 'faculty_start_year', 'faculty_start_month',
            'faculty_end_year', 'faculty_end_month', 'home_phone_no',
            'office_phone_no', 'current_location', 'home_town', 'correspondence_address',
            'correspondence_city', 'correspondence_state', 'correspondence_country',
            'correspondence_pincode', 'company', 'position', 'member_roles', 'educational_course', 'educational_institute',
            'start_year', 'end_year', 'facebook_link', 'linkedin_link', 'twitter_link',
            'website_link', 'work_experience', 'professional_skills', 'industries_worked_in',
            'roles_played', 'chapter', 'college_name', 'role', 'phone', 'Address', 'city',
            'state', 'country', 'zip_code', 'branch', 'social_links', 'profile_photo',
            'cover_photo', 'bio', 'passed_out_year', 'current_work',
            'Worked_in', 'experience'
        ]
        extra_kwargs = {'password': {'write_only': True}}

class LoginLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.LoginLog
        fields = ['id', 'user', 'user_agent', 'timestamp']
class memberSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.CustomUser
        fields = [
            'username', 'first_name', 'last_name', 'email', 'contact_number', 
            'passed_out_year', 'current_work', 'experience', 'social_links', 
            'profile_photo', 'cover_photo', 'bio'
        ]

class EventImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.EventImage
        fields = ['id', 'image']

class EventSerializer(serializers.ModelSerializer):
    images = EventImageSerializer(many=True, required=False)
    
    class Meta:
        model = models.Events
        fields = ['id', 'user', 'uploaded_on', 'description', 'title', 'venue', 'from_date_time', 'end_date_time', 'tag', 'uploaded_by', 'images']

    def create(self, validated_data):
        images_data = validated_data.pop('images', [])
        event = models.Events.objects.create(**validated_data)
        for image_data in images_data:
            models.EventImage.objects.create(event=event, **image_data)
        return event

    def update(self, instance, validated_data):
        images_data = validated_data.pop('images', None)
        instance = super().update(instance, validated_data)
        if images_data is not None:
            instance.images.all().delete()
            for image_data in images_data:
                models.EventImage.objects.create(event=instance, **image_data)
        return instance

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
        # Check if obj.user exists and return user details directly
        if obj.user:
            return {
                "first_name": obj.user.first_name,
                "last_name": obj.user.last_name,
                "username": obj.user.username,
                "profile_photo": obj.user.profile_photo.url if obj.user.profile_photo else ""
            }
        return None

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

    user_details = serializers.SerializerMethodField()

    class Meta:
        model = models.user_location
        fields = ['id', 'user', 'user_details', 'latitude', 'longitude']
        read_only_fields = ['id', 'user', 'user_details']

    def get_user_details(self, obj):
        user = obj.user
        if user:
            return UserSerializer(user).data
        return None
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request:
            user = validated_data.pop('user', None) or self.context['request'].user
            try:
                instance = models.user_location.objects.get(user=user)
                instance.latitude = validated_data.get('latitude', instance.latitude)
                instance.longitude = validated_data.get('longitude', instance.longitude)
                instance.save()
                return instance
            except models.user_location.DoesNotExist:
                return models.user_location.objects.create(user=user, **validated_data)
        return super().create(validated_data)

class BusinessImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.BusinessImage
        fields = ['id', 'image', 'caption']

class BusinessDirectorySerializer(serializers.ModelSerializer):
    owner_details = serializers.SerializerMethodField()
    images = BusinessImageSerializer(many=True, read_only=True)
    
    class Meta:
        model = models.BusinessDirectory
        fields = [
            'id', 'owner', 'owner_details', 'business_name', 'description', 
            'category', 'website', 'email', 'phone', 'address', 'city', 
            'state', 'country', 'postal_code', 'year_founded', 
            'employee_count', 'logo', 'social_media', 'keywords', 
            'is_active', 'created_at', 'updated_at', 'images'
        ]
        read_only_fields = ['id', 'owner', 'owner_details', 'created_at', 'updated_at']
    
    def get_owner_details(self, obj):
        return {
            "id": obj.owner.id,
            "username": obj.owner.username,
            "first_name": obj.owner.first_name,
            "last_name": obj.owner.last_name,
            "profile_photo": obj.owner.profile_photo.url if obj.owner.profile_photo else None,
        }
    
class NewsImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.NewsImage
        fields = ['id', 'image', 'caption']

class NewsRoomSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    images = NewsImageSerializer(many=True, read_only=True)
    
    class Meta:
        model = models.NewsRoom
        fields = [
            'id', 'user', 'title', 'content', 'published_on', 'updated_on',
            'thumbnail', 'category', 'status', 'featured', 'views', 'images'
        ]
        read_only_fields = ['id', 'user', 'published_on', 'updated_on', 'views']
    
    def get_user(self, obj):
        return {
            "id": obj.user.id,
            "username": obj.user.username,
            "first_name": obj.user.first_name,
            "last_name": obj.user.last_name,
            "profile_photo": obj.user.profile_photo.url if obj.user.profile_photo else None,
        }