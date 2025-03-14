from django.db import models
from django.contrib.auth import get_user_model
from phonenumber_field.modelfields import PhoneNumberField

User = get_user_model()

def get_default_reaction():
    return {
        "like": 0,
        "love": 0,
        "haha": 0,
        "wow": 0,
        "sad": 0
    }

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

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    email = models.EmailField(max_length=255, blank=True)
    social_links = models.JSONField(
        default=get_default_social_links,
        blank=True
    )  # Social media links
    profile_photo = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    cover_photo = models.ImageField(upload_to='cover_pics/', null=True, blank=True)

    def sync_user(self):
        """
        Synchronize the Profile's first name, last name, and email with the User model.
        """
        if self.user:
            updated = False
            if self.first_name and self.first_name != self.user.first_name:
                self.user.first_name = self.first_name
                updated = True
            if self.last_name and self.last_name != self.user.last_name:
                self.user.last_name = self.last_name
                updated = True
            if self.email and self.email != self.user.email:
                self.user.email = self.email
                updated = True
            if updated:
                self.user.save()
    bio = models.TextField(max_length=500, blank=True)
    contact_number = PhoneNumberField(blank=True, default="+911234567890")
    passed_out_year = models.PositiveIntegerField(null=True, blank=True) 
    current_work = models.CharField(max_length=255, blank=True)  
    previous_work = models.JSONField(default=list, blank=True) 
    experience = models.JSONField(default=list, blank=True)  
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.username}"

    def save(self, *args, **kwargs):
        if self.pk:
            original = Profile.objects.get(pk=self.pk)
            if original.current_work != self.current_work and original.current_work:
                prev_list = self.previous_work if isinstance(self.previous_work, list) else []
                if original.current_work not in prev_list:
                    prev_list.append(original.current_work)
                    self.previous_work = prev_list
        super().save(*args, **kwargs)

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

