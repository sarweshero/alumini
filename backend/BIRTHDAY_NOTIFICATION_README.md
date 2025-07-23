# Birthday Notification System

This system automatically sends birthday notifications to batchmates using Celery for asynchronous email processing.

## Features

- **Automated Daily Notifications**: Runs daily to check for birthdays
- **Today's Birthdays**: Sends immediate notifications for today's birthdays  
- **Upcoming Birthdays**: Sends advance notifications 3 days before birthdays
- **Batchmate Detection**: Finds batchmates based on college, course, and graduation year
- **Professional Email Templates**: Beautiful HTML emails with fallback plain text
- **Manual Triggers**: API endpoints and management commands for manual testing

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install and Start Redis (Windows)

```bash
# Download Redis for Windows or use WSL
# Or use Docker:
docker run -d -p 6379:6379 redis:latest
```

### 3. Run Database Migrations

```bash
python manage.py migrate
python manage.py migrate django_celery_beat
```

### 4. Start Services

#### Option A: Using the batch script (Windows)
```bash
start_celery.bat
```

#### Option B: Manual start
```bash
# Terminal 1 - Start Celery Worker
celery -A backend worker --loglevel=info --pool=solo

# Terminal 2 - Start Celery Beat (Scheduler)  
celery -A backend beat --loglevel=info

# Terminal 3 - Start Django server
python manage.py runserver
```

## API Endpoints

### 1. Get Birthday List
```http
GET /api/birthdays/
```
Returns users with birthdays in the next 15 days.

### 2. Send Birthday Notifications
```http
POST /api/birthdays/
Content-Type: application/json

{
    "user_ids": [1, 2, 3],        // Send for specific users
    "send_all_today": true,       // Send for all today's birthdays
    "notify_upcoming": true       // Send for upcoming birthdays (3 days)
}
```

## Management Commands

### Test Birthday Notifications (No Emails Sent)

```bash
# Test daily check
python manage.py send_birthday_notifications --daily-check --test

# Test specific user
python manage.py send_birthday_notifications --user-id 1 --test

# Test today's birthdays
python manage.py send_birthday_notifications --all-today --test

# Test upcoming birthdays
python manage.py send_birthday_notifications --upcoming --test
```

### Send Actual Notifications

```bash
# Run daily check (sends both today and upcoming)
python manage.py send_birthday_notifications --daily-check

# Send for specific user
python manage.py send_birthday_notifications --user-id 1

# Send for all today's birthdays
python manage.py send_birthday_notifications --all-today

# Send for upcoming birthdays (3 days)
python manage.py send_birthday_notifications --upcoming
```

## How It Works

### 1. Batchmate Detection

The system finds batchmates using these criteria (in order of priority):

1. **Primary**: Same college name + same passed out year
2. **Secondary**: Same college name + same course end year  
3. **Tertiary**: Same course + same passed out year

### 2. Email Content

Birthday notifications include:
- Person's name whose birthday it is
- Their batch/graduation information
- Days until birthday (0 for today, 3 for upcoming)
- Professional HTML formatting with plain text fallback

### 3. Automated Schedule

- **Daily at 8:00 AM UTC**: Checks for today's birthdays and upcoming birthdays (3 days)
- **Celery Beat**: Manages the daily schedule
- **Celery Worker**: Processes email sending tasks asynchronously

### 4. Error Handling

- Handles leap year edge cases (Feb 29)
- Retries failed email sends up to 3 times
- Logs all activities for monitoring
- Graceful handling of missing user data

## Configuration

### Email Settings (settings.py)
```python
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "your-email@gmail.com"
EMAIL_HOST_PASSWORD = "your-app-password"
```

### Celery Settings (settings.py)
```python
CELERY_BROKER_URL = 'redis://0.0.0.0:6379/0'
CELERY_RESULT_BACKEND = 'redis://0.0.0.0:6379/0'
CELERY_TIMEZONE = 'UTC'
```

### Schedule Customization (backend/celery.py)

To change the daily notification time:
```python
app.conf.beat_schedule = {
    'send-birthday-notifications': {
        'task': 'api.tasks.send_daily_birthday_notifications',
        'schedule': crontab(hour=8, minute=0),  # 8:00 AM UTC
    },
}
```

## Monitoring

### Check Celery Status
```bash
# Monitor worker
celery -A backend inspect active

# Monitor scheduled tasks
celery -A backend inspect scheduled

# Check task results
celery -A backend result <task-id>
```

### Logs
- Worker logs show task execution
- Beat logs show scheduling
- Django logs show API requests
- Email sending results are logged

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   - Ensure Redis is running on port 6379
   - Check Redis connection: `redis-cli ping`

2. **Email Not Sending**
   - Verify SMTP settings
   - Check email credentials
   - Enable "Less secure app access" for Gmail or use App Passwords

3. **Tasks Not Executing**
   - Ensure Celery worker is running
   - Check for task failures in logs
   - Verify Redis is accessible

4. **No Batchmates Found**
   - Check user data completeness (college_name, passed_out_year, etc.)
   - Verify users have is_active=True
   - Test with the management command using --test flag

### Debug Commands

```bash
# Test Redis connection
redis-cli ping

# Check user data
python manage.py shell
>>> from django.contrib.auth import get_user_model
>>> User = get_user_model()
>>> user = User.objects.get(id=1)
>>> print(user.college_name, user.passed_out_year, user.date_of_birth)

# Manual task execution
python manage.py shell
>>> from api.tasks import send_birthday_notifications_to_batchmates
>>> result = send_birthday_notifications_to_batchmates.delay(1, days_until=0)
>>> print(result.result)
```

## Production Deployment

### Using Supervisor (Linux)

Create `/etc/supervisor/conf.d/celery.conf`:
```ini
[program:celery-worker]
command=/path/to/venv/bin/celery -A backend worker --loglevel=info
directory=/path/to/project
user=www-data
autostart=true
autorestart=true

[program:celery-beat]
command=/path/to/venv/bin/celery -A backend beat --loglevel=info
directory=/path/to/project
user=www-data
autostart=true
autorestart=true
```

### Using Docker

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  redis:
    image: redis:latest
    ports:
      - "6379:6379"
  
  celery-worker:
    build: .
    command: celery -A backend worker --loglevel=info
    depends_on:
      - redis
  
  celery-beat:
    build: .
    command: celery -A backend beat --loglevel=info
    depends_on:
      - redis
```

## Support

For issues or questions:
1. Check the logs for error messages
2. Use the test commands to debug
3. Verify Redis and email settings
4. Contact the development team
