@echo off
echo Starting Celery services for Alumni Portal...

echo.
echo Starting Redis server (make sure Redis is installed and running)
echo If Redis is not running, start it with: redis-server

echo.
echo Starting Celery Worker...
start "Celery Worker" cmd /k "cd /d %~dp0 && celery -A backend worker --loglevel=info --pool=solo"

timeout /t 3 /nobreak >nul

echo.
echo Starting Celery Beat (Scheduler)...
start "Celery Beat" cmd /k "cd /d %~dp0 && celery -A backend beat --loglevel=info"

echo.
echo Celery services started!
echo.
echo Worker: Processes background tasks
echo Beat: Schedules daily birthday notifications
echo.
echo Press any key to exit...
pause >nul
