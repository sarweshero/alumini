from django.db import models
from django.contrib.auth import get_user_model
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import AbstractUser, Group, Permission
User = get_user_model()
def get_default_social_links():
    return {
        "Github": "",
        "LinkedIn": "",
        "Instagram": "",
        "Facebook": "",
        "X": "",
        "StackOverflow": "",
        "Pinterest": "",
        "YouTube": "",
    }


class CustomUser(AbstractUser):
    college_name = models.CharField(max_length=500)
    role = models.CharField(max_length=50)
    phone = models.CharField(max_length=20)
    social_links = models.JSONField(default=get_default_social_links, blank=True)
    profile_photo = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    cover_photo = models.ImageField(upload_to='cover_pics/', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    contact_number = PhoneNumberField(blank=True, default="+911234567890")
    passed_out_year = models.PositiveIntegerField(null=True, blank=True)
    current_work = models.CharField(max_length=255, blank=True)
    previous_work = models.JSONField(default=list, blank=True)
    experience = models.JSONField(default=list, blank=True)
    groups = models.ManyToManyField(
        Group,
        related_name="customuser_set",  # Custom reverse accessor
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups"
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_set",  # Custom reverse accessor
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions"
    )

    def update_is_staff(self):
        """Set is_staff flag based on the user's role."""
        self.is_staff = self.role != "Student"

    def update_previous_work(self):
        """Update previous_work if current_work has changed."""
        if self.pk:
            original = CustomUser.objects.get(pk=self.pk)
            if original.current_work != self.current_work and original.current_work:
                prev_list = self.previous_work if isinstance(self.previous_work, list) else []
                if original.current_work not in prev_list:
                    prev_list.append(original.current_work)
                    self.previous_work = prev_list

    def save(self, *args, **kwargs):
        """Save method with separated logic for clarity."""
        self.update_is_staff()
        self.update_previous_work()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username



class PendingSignup(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    college_name = models.CharField(max_length=500)
    role = models.CharField(max_length=50)
    phone = models.CharField(max_length=20)
    social_links = models.JSONField(default=get_default_social_links, blank=True)
    profile_photo = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    cover_photo = models.ImageField(upload_to='cover_pics/', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    contact_number = PhoneNumberField(blank=True, default="+911234567890")
    passed_out_year = models.PositiveIntegerField(null=True, blank=True)
    current_work = models.CharField(max_length=255, blank=True)
    previous_work = models.JSONField(default=list, blank=True)
    experience = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    approved_at = models.DateTimeField(null=True, blank=True)
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)

    def __str__(self):
        return f"PendingSignup: {self.email}"

def get_default_reaction():
    return {
        "like": 0,
        "love": 0,
        "haha": 0,
        "wow": 0,
        "sad": 0
    }

class LoginLog(models.Model):
    """
    Optionally log each login attempt for auditing purposes.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    successful = models.BooleanField(default=False)
    browser = models.CharField(max_length=100, null=True, blank=True)
    browser_version = models.CharField(max_length=20, null=True, blank=True)
    device = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.ip_address} - {self.browser}"
        
        
class Events(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='events')
    uploaded_on = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    venue = models.CharField(max_length=255)
    from_date_time = models.DateTimeField(null=False)
    end_date_time = models.DateTimeField(null=True, blank=True)
    image = models.ImageField(upload_to='event_images/', null=True, blank=True)
    tag = models.CharField(max_length=255, blank=True)
    uploaded_by = models.CharField(
        max_length=10,
        choices=[('user', 'User'), ('staff', 'Staff'), ('admin', 'Admin')],
        default='user'
    )

    def __str__(self):
        return f"{self.title} at {self.venue}, created by {self.user.username}"


class Jobs(models.Model):
    """
    Job postings for the alumni portal.
    
    Suggestions integrated:
      - Separate comments into a related model (JobComment) for multiple comments.
      - Expand reaction into a JSONField to support various reaction types.
      - Additional fields like salary_range and job_type are added.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='jobs')
    company_name = models.CharField(max_length=255)
    posted_on = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=255)
    role = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    salary_range = models.CharField(max_length=100, blank=True)
    job_type = models.CharField(max_length=100, blank=True)  # e.g., Full-Time, Part-Time
    views = models.PositiveIntegerField(default=0)
    reaction = models.JSONField(
        default=get_default_reaction,
        blank=True
    )
    def __str__(self):
        return f"{self.company_name} - {self.role} by {self.user.username}"

class JobImage(models.Model):
    """
    Handles multiple image uploads for a job posting.
    """
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='job_images/')

    def __str__(self):
        return f"Image for {self.job.company_name} - {self.job.role}"


class JobComment(models.Model):
    """
    Separate model for job comments to allow multiple comments per job.
    """
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='job_comments')
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.job.company_name} - {self.job.role}"


class JobReaction(models.Model):
    job = models.ForeignKey(Jobs, on_delete=models.CASCADE, related_name='reactions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='job_reactions')
    reaction = models.CharField(max_length=20)

    class Meta:
        unique_together = ('job', 'user')

    def __str__(self):
        return f"{self.user.username} reacted {self.reaction} to {self.job.company_name} - {self.job.role}"


class Album(models.Model):
    """
    Represents a college album posted by admin or staff.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='albums')
    posted_on = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    cover_image = models.ImageField(upload_to='album_covers/', null=True, blank=True)

    def __str__(self):
        return f"Album: {self.title} by {self.user.username}"


class AlbumImage(models.Model):
    """
    Additional images for an album.
    """
    album = models.ForeignKey(Album, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='album_images/')

    def __str__(self):
        return f"Image for album: {self.album.title}"