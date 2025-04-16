from django.db import models
from django.contrib.auth import get_user_model
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import AbstractUser, Group, Permission


def default_reaction():
    return {"like": 0}

def get_default_social_links():
    return {
        "Github": "",
        "LinkedIn": "",
        "Instagram": "",
        "Facebook": "",
        "X": "",
        "Website": ""
    }

class CustomUser(AbstractUser):
    # Basic Info
    salutation = models.CharField(max_length=20, blank=True)
    name = models.CharField(max_length=255, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    label = models.CharField(max_length=255, blank=True)
    email = models.EmailField(unique=True)
    secondary_email = models.EmailField(blank=True)
    registered = models.CharField(max_length=10, blank=True)
    registered_on = models.CharField(max_length=20, blank=True)
    approved_on = models.CharField(max_length=20, blank=True)
    profile_updated_on = models.CharField(max_length=20, blank=True)
    admin_note = models.TextField(blank=True)
    profile_type = models.CharField(max_length=50, blank=True)
    roll_no = models.CharField(max_length=100, blank=True)
    course = models.CharField(max_length=255, blank=True)
    stream = models.CharField(max_length=255, blank=True)
    course_start_year = models.CharField(max_length=10, blank=True)
    course_end_year = models.CharField(max_length=10, blank=True)
    faculty_job_title = models.CharField(max_length=255, blank=True)
    faculty_institute = models.CharField(max_length=255, blank=True)
    faculty_department = models.CharField(max_length=255, blank=True)
    faculty_start_year = models.CharField(max_length=10, blank=True)
    faculty_start_month = models.CharField(max_length=10, blank=True)
    faculty_end_year = models.CharField(max_length=10, blank=True)
    faculty_end_month = models.CharField(max_length=10, blank=True)
    home_phone_no = models.CharField(max_length=30, blank=True)
    office_phone_no = models.CharField(max_length=30, blank=True)
    current_location = models.CharField(max_length=255, blank=True)
    home_town = models.CharField(max_length=255, blank=True)
    correspondence_address = models.TextField(blank=True)
    correspondence_city = models.CharField(max_length=255, blank=True)
    correspondence_state = models.CharField(max_length=255, blank=True)
    correspondence_country = models.CharField(max_length=255, blank=True)
    correspondence_pincode = models.CharField(max_length=20, blank=True)
    company = models.CharField(max_length=255, blank=True)
    position = models.CharField(max_length=255, blank=True)
    member_roles = models.CharField(max_length=255, blank=True)
    educational_course = models.CharField(max_length=255, blank=True)
    educational_institute = models.CharField(max_length=255, blank=True)
    start_year = models.CharField(max_length=10, blank=True)
    end_year = models.CharField(max_length=10, blank=True)
    facebook_link = models.URLField(blank=True)
    linkedin_link = models.URLField(blank=True)
    twitter_link = models.URLField(blank=True)
    website_link = models.URLField(blank=True)
    work_experience = models.FloatField(null=True, blank=True)
    professional_skills = models.JSONField(default=list, blank=True)
    industries_worked_in = models.JSONField(default=list, blank=True)
    roles_played = models.JSONField(default=list, blank=True)
    chapter = models.CharField(max_length=255, blank=True)
    college_name = models.CharField(max_length=500, blank=True)
    role = models.CharField(max_length=50, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    Address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    zip_code = models.CharField(max_length=20, blank=True)
    branch = models.CharField(max_length=255, blank=True)
    social_links = models.JSONField(default=get_default_social_links, blank=True)
    profile_photo = models.FileField(upload_to='profile_pics/', null=True, blank=True)
    cover_photo = models.FileField(upload_to='cover_pics/', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    passed_out_year = models.CharField(max_length=20, null=True, blank=True)
    current_work = models.CharField(max_length=255, blank=True)
    Worked_in = models.JSONField(default=list, blank=True)
    experience = models.JSONField(default=list, blank=True)

    # Django auth fields
    groups = models.ManyToManyField(
        Group,
        related_name="customuser_set",
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups"
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_set",
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions"
    )

    def update_is_staff(self):
        """Set is_staff flag based on the user's role."""
        self.is_staff = self.role != "Student"

    def save(self, *args, **kwargs):
        self.update_is_staff()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

User = get_user_model()

class SignupOTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Signup OTP for {self.email}: {self.code}"

class PendingSignup(models.Model):
    # Basic Info
    salutation = models.CharField(max_length=20, blank=True)
    name = models.CharField(max_length=255, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    label = models.CharField(max_length=255, blank=True)
    email = models.EmailField(null=True)
    secondary_email = models.EmailField(blank=True)
    approved_on = models.CharField(max_length=20, blank=True)
    profile_type = models.CharField(max_length=50, blank=True)
    roll_no = models.CharField(max_length=100, blank=True)
    course = models.CharField(max_length=255, blank=True)
    stream = models.CharField(max_length=255, blank=True)
    course_start_year = models.CharField(max_length=10, blank=True)
    course_end_year = models.CharField(max_length=10, blank=True)
    faculty_job_title = models.CharField(max_length=255, blank=True)
    faculty_institute = models.CharField(max_length=255, blank=True)
    faculty_department = models.CharField(max_length=255, blank=True)
    faculty_start_year = models.CharField(max_length=10, blank=True)
    faculty_start_month = models.CharField(max_length=10, blank=True)
    faculty_end_year = models.CharField(max_length=10, blank=True)
    faculty_end_month = models.CharField(max_length=10, blank=True)
    office_phone_no = models.CharField(max_length=30, blank=True)
    current_location = models.CharField(max_length=255, blank=True)
    home_town = models.CharField(max_length=255, blank=True)
    correspondence_address = models.TextField(blank=True)
    correspondence_city = models.CharField(max_length=255, blank=True)
    correspondence_state = models.CharField(max_length=255, blank=True)
    correspondence_country = models.CharField(max_length=255, blank=True)
    correspondence_pincode = models.CharField(max_length=20, blank=True)
    company = models.CharField(max_length=255, blank=True)
    position = models.CharField(max_length=255, blank=True)
    member_roles = models.CharField(max_length=255, blank=True)
    educational_course = models.CharField(max_length=255, blank=True)
    educational_institute = models.CharField(max_length=255, blank=True)
    start_year = models.CharField(max_length=10, blank=True)
    end_year = models.CharField(max_length=10, blank=True)
    facebook_link = models.URLField(blank=True)
    linkedin_link = models.URLField(blank=True)
    twitter_link = models.URLField(blank=True)
    website_link = models.URLField(blank=True)
    work_experience = models.FloatField(null=True, blank=True, default=0.0)
    professional_skills = models.JSONField(default=list, blank=True)
    industries_worked_in = models.JSONField(default=list, blank=True)
    roles_played = models.JSONField(default=list, blank=True)
    chapter = models.CharField(max_length=255, blank=True)
    college_name = models.CharField(max_length=500, blank=True)
    role = models.CharField(max_length=50, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    Address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=255, blank=True)
    zip_code = models.CharField(max_length=20, blank=True)
    branch = models.CharField(max_length=255, blank=True)
    social_links = models.JSONField(default=get_default_social_links, blank=True)
    profile_photo = models.FileField(upload_to='profile_pics/', null=True, blank=True)
    cover_photo = models.FileField(upload_to='cover_pics/', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    passed_out_year = models.CharField(max_length=20, null=True, blank=True)
    current_work = models.CharField(max_length=255, blank=True)
    Worked_in = models.JSONField(default=list, blank=True)
    experience = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)

    def __str__(self):
        return f"PendingSignup: {self.email}"


class LoginLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_agent = models.CharField(max_length=255, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"LoginLog for {self.user.username} at {self.timestamp}"

class Events(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='events')
    uploaded_on = models.DateTimeField(auto_now_add=True)
    description = models.TextField(blank=True)
    title = models.CharField(max_length=255)
    venue = models.CharField(max_length=255)
    from_date_time = models.DateTimeField(null=False)
    end_date_time = models.DateTimeField(null=True, blank=True)
    tag = models.CharField(max_length=255, blank=True)
    uploaded_by = models.CharField(
        max_length=10,
        choices=[('Student', 'Student'), ('Staff', 'Staff'), ('Admin', 'Admin')],
        default='Student'
    )

    def __str__(self):
        return f"{self.title} at {self.venue}, created by {self.user.username}"

# New model to allow multiple images per event
class EventImage(models.Model):
    event = models.ForeignKey(Events, on_delete=models.CASCADE, related_name='images')
    image = models.FileField(upload_to='event_images/', null=True, blank=True)

    def __str__(self):
        return f"Image for {self.event.title}"

class Jobs(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='jobs')
    company_name = models.CharField(max_length=255, null=True, blank=True)
    posted_on = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    role = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    isjob = models.BooleanField(default=False)
    salary_range = models.CharField(max_length=100, blank=True)
    job_type = models.CharField(max_length=100, blank=True)
    # Only tracking likes with a serializable default
    reaction = models.JSONField(default=default_reaction)  

    def __str__(self):
        return f"{self.company_name} - {self.role} by {self.user.username}"


class JobReaction(models.Model):
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='reactions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='job_reactions')
    # Since only 'like' reactions are supported, we default the value to "like"
    reaction = models.CharField(max_length=20, default="like")

    class Meta:
        unique_together = ('job', 'user')

    def __str__(self):
        return f"{self.user.username} liked {self.job.company_name} - {self.job.role}"

class JobImage(models.Model):
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='images')
    image = models.FileField(upload_to='job_images/')

    def __str__(self):
        return f"Image for {self.job.company_name} - {self.job.role}"

class user_location(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='location')
    latitude = models.CharField(max_length=50)
    longitude = models.CharField(max_length=50)
    
    def __str__(self):
        return f"{self.user.username} - ({self.latitude}, {self.longitude})"

class JobComment(models.Model):
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='job_comments')
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.job.company_name} - {self.job.role}"


class Album(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='albums')
    posted_on = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    cover_image = models.FileField(upload_to='album_covers/', null=True, blank=True)

    def __str__(self):
        return f"Album: {self.title} by {self.user.username}"

class AlbumImage(models.Model):
    album = models.ForeignKey(Album, on_delete=models.CASCADE, related_name='images')
    image = models.FileField(upload_to='album_images/')

    def __str__(self):
        return f"Image for album: {self.album.title}"