from django.apps import AppConfig
from django.contrib.auth import get_user_model
from django.db.models.signals import post_migrate


class YourAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        User = get_user_model()
        def create_default_admin(sender, **kwargs):
            if not User.objects.filter(username="admin").exists():
                User.objects.create_superuser("admin", "admin@example.com", "Admin@123.in")
                # print("Default admin user created: admin / Admin@123.in")
        post_migrate.connect(create_default_admin, sender=self)