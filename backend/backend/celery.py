# import os
# from celery import Celery
# from celery.schedules import crontab

# # Set the default Django settings module for the 'celery' program.
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

# app = Celery('backend')

# # Using a string here means the worker doesn't have to serialize
# # the configuration object to child processes.
# app.config_from_object('django.conf:settings', namespace='CELERY')

# # Load task modules from all registered Django apps.
# app.autodiscover_tasks()

# # Celery Beat schedule for periodic tasks
# app.conf.beat_schedule = {
#     'send-birthday-notifications': {
#         'task': 'api.tasks.send_daily_birthday_notifications',
#         'schedule': crontab(hour=8, minute=0),  # Run daily at 8:00 AM UTC
#         'options': {'expires': 3600}  # Task expires in 1 hour if not executed
#     },
# }

# app.conf.timezone = 'UTC'

# @app.task(bind=True)
# def debug_task(self):
#     print(f'Request: {self.request!r}')

import os
from celery import Celery

# use the same settings module you export
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

app = Celery("backend")

# read config from Django settings with CELERY_ prefix
app.config_from_object("django.conf:settings", namespace="CELERY")

# auto-discover tasks in installed apps
app.autodiscover_tasks()
