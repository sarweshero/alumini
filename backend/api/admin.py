from django.contrib import admin
from .models import Profile, LoginLog, Events, Album, AlbumImage, Jobs, JobImage, JobComment, JobReaction  # Import Jobs, JobImage, JobComment, JobReaction
from django.utils.html import format_html

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'first_name', 'last_name', 'contact_number')
    search_fields = ('user__username', 'first_name', 'last_name')

@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'timestamp', 'ip_address', 'successful', 'browser')
    list_filter = ('successful', 'user')

class AlbumImageInline(admin.TabularInline):
    model = AlbumImage
    extra = 1

@admin.register(Album)
class AlbumAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'cover_image')
    search_fields = ('title',)
    inlines = [AlbumImageInline]

    def display_photos(self, obj):
        if obj.photos.exists():
            images_html = ''.join([
                f'<img src="{photo.image.url}" style="width: 50px; height: 50px; object-fit: cover; margin-right: 5px;" />'
                for photo in obj.photos.all()
            ])
            return format_html(images_html)
        return "-"
    display_photos.short_description = "Album Images"

@admin.register(Events)
class EventsAdmin(admin.ModelAdmin):
    def get_list_display(self, request):
        return [field.name for field in self.model._meta.fields]
    search_fields = ('title', 'venue', 'user__username')

class JobImageInline(admin.TabularInline):
    model = JobImage
    extra = 1

@admin.register(Jobs)
class JobsAdmin(admin.ModelAdmin):
    list_display = ('company_name', 'role', 'location', 'posted_on', 'user')
    search_fields = ('company_name', 'role', 'location', 'user__username')
    inlines = [JobImageInline]

@admin.register(JobComment)
class JobCommentAdmin(admin.ModelAdmin):
    list_display = ('job', 'user', 'comment', 'created_at')
    search_fields = ('job__company_name', 'user__username', 'comment')

@admin.register(JobReaction)
class JobReactionAdmin(admin.ModelAdmin):
    list_display = ('job', 'user', 'reaction')
    search_fields = ('job__company_name', 'user__username', 'reaction')


