@echo off
echo Setting up Birthday Notification System...

echo.
echo 1. Installing Python dependencies...
pip install -r requirements.txt

echo.
echo 2. Running database migrations...
python manage.py migrate
python manage.py migrate django_celery_beat

echo.
echo 3. Creating superuser (if needed)...
echo You can skip this if you already have an admin user
python manage.py createsuperuser

echo.
echo 4. Setup complete!
echo.
echo Next steps:
echo 1. Make sure Redis is running (redis-server)
echo 2. Start Celery services: start_celery.bat
echo 3. Start Django server: python manage.py runserver
echo.
echo For testing: python manage.py send_birthday_notifications --daily-check --test
echo.
pause
