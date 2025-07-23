from celery import shared_task
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.conf import settings
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


def send_birthday_notification_email(recipient_email, birthday_person_name, birthday_person_batch, days_until=0):
    """Send birthday notification email to batchmates."""
    
    if days_until == 0:
        subject = f"🎉 It's {birthday_person_name}'s Birthday Today!"
        greeting = "Happy Birthday"
        message_body = f"Today is the birthday of our fellow alumnus <strong>{birthday_person_name}</strong> from batch {birthday_person_batch}!"
    else:
        subject = f"🎂 Upcoming Birthday - {birthday_person_name} ({days_until} days)"
        greeting = "Upcoming Birthday"
        message_body = f"In {days_until} days, it will be the birthday of our fellow alumnus <strong>{birthday_person_name}</strong> from batch {birthday_person_batch}!"
    
    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 20px;">
        <div style="background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #e74c3c; margin: 0;">🎉 {greeting} Notification 🎂</h2>
            </div>
            
            <div style="background-color: #fff5f5; padding: 20px; border-radius: 8px; margin: 25px 0; text-align: center; border-left: 4px solid #e74c3c;">
                <h3 style="color: #e74c3c; margin: 0 0 15px 0;">🎈 Birthday Alert!</h3>
                <p style="color: #2c3e50; font-size: 16px; line-height: 1.6; margin: 0;">
                    {message_body}
                </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <p style="color: #34495e; font-size: 16px; line-height: 1.6;">
                    Let's come together to celebrate and make this day special! 🌟
                </p>
            </div>
            
            <div style="background-color: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #27ae60;">
                <p style="color: #27ae60; margin: 0; font-size: 14px;">
                    <strong>🎊 Celebration Idea:</strong> Consider reaching out to wish them personally or organize a virtual celebration!
                </p>
            </div>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ecf0f1;">
                <p style="color: #7f8c8d; font-size: 14px; margin: 0;">
                    Bringing our alumni community together! 🤗<br>
                    <strong style="color: #2c3e50;">The Alumni Portal Team</strong>
                </p>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <p style="color: #7f8c8d; font-size: 12px;">
                This is an automated birthday notification from Alumni Portal.
            </p>
        </div>
    </div>
    """
    
    plain_message = f"""
    🎉 {greeting} Notification 🎂
    
    🎈 Birthday Alert!
    {message_body.replace('<strong>', '').replace('</strong>', '')}
    
    Let's come together to celebrate and make this day special! 🌟
    
    🎊 Celebration Idea: Consider reaching out to wish them personally or organize a virtual celebration!
    
    Bringing our alumni community together! 🤗
    The Alumni Portal Team
    
    ---
    This is an automated birthday notification from Alumni Portal.
    """
    
    try:
        email_message = EmailMessage(
            subject=subject,
            body=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[recipient_email],
        )
        email_message.attach_alternative(html_message, "text/html")
        email_message.send(fail_silently=False)
        return True
    except Exception as e:
        logger.error(f"Failed to send birthday notification to {recipient_email}: {str(e)}")
        return False


@shared_task(bind=True, max_retries=3)
def send_birthday_notifications_to_batchmates(self, birthday_user_id, days_until=0):
    """
    Send birthday notifications to all batchmates of a birthday person.
    
    Args:
        birthday_user_id: ID of the user whose birthday it is
        days_until: Number of days until birthday (0 for today)
    """
    try:
        # Get the birthday person
        birthday_user = User.objects.get(id=birthday_user_id)
        
        # Find batchmates using multiple criteria
        batchmates_query = Q()
        
        # Match by college name and passed out year (primary criteria)
        if birthday_user.college_name and birthday_user.passed_out_year:
            batchmates_query |= Q(
                college_name__iexact=birthday_user.college_name,
                passed_out_year=birthday_user.passed_out_year
            )
        
        # Match by college name and course end year (secondary criteria)
        if birthday_user.college_name and birthday_user.course_end_year:
            batchmates_query |= Q(
                college_name__iexact=birthday_user.college_name,
                course_end_year=birthday_user.course_end_year
            )
        
        # Match by course and passed out year (tertiary criteria)
        if birthday_user.course and birthday_user.passed_out_year:
            batchmates_query |= Q(
                course__iexact=birthday_user.course,
                passed_out_year=birthday_user.passed_out_year
            )
        
        # Get batchmates (excluding the birthday person themselves)
        batchmates = User.objects.filter(batchmates_query).exclude(
            id=birthday_user_id
        ).exclude(
            email__isnull=True
        ).exclude(
            email=""
        ).filter(
            is_active=True
        )
        
        successful_sends = 0
        failed_sends = 0
        
        # Determine batch info for the email
        batch_info = birthday_user.passed_out_year or birthday_user.course_end_year or "Unknown"
        if birthday_user.college_name:
            batch_info = f"{birthday_user.college_name} - {batch_info}"
        
        # Send notification to each batchmate
        for batchmate in batchmates:
            if send_birthday_notification_email(
                recipient_email=batchmate.email,
                birthday_person_name=birthday_user.first_name or birthday_user.username,
                birthday_person_batch=batch_info,
                days_until=days_until
            ):
                successful_sends += 1
            else:
                failed_sends += 1
        
        logger.info(
            f"Birthday notifications sent for {birthday_user.first_name or birthday_user.username}: "
            f"{successful_sends} successful, {failed_sends} failed"
        )
        
        return {
            'birthday_person': birthday_user.first_name or birthday_user.username,
            'successful_sends': successful_sends,
            'failed_sends': failed_sends,
            'total_batchmates': batchmates.count(),
            'days_until': days_until
        }
        
    except User.DoesNotExist:
        logger.error(f"Birthday user with ID {birthday_user_id} not found")
        return {'error': 'Birthday user not found'}
    except Exception as exc:
        logger.error(f"Error sending birthday notifications: {str(exc)}")
        # Retry the task
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@shared_task
def send_daily_birthday_notifications():
    """
    Daily task to check for birthdays and send notifications.
    This task should be run daily via Celery Beat.
    """
    today = timezone.now().date()
    users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)

    birthday_notifications_sent = 0
    upcoming_notifications_sent = 0

    for user in users_with_birthdays:
        birth_month = user.date_of_birth.month
        birth_day = user.date_of_birth.day

        # Calculate next birthday, handle leap year issue
        try:
            next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
        except ValueError:
            # Handle Feb 29 on non-leap years by using Feb 28
            if birth_month == 2 and birth_day == 29:
                next_birthday = timezone.datetime(today.year, 2, 28).date()
            else:
                continue  # skip invalid dates

        if next_birthday < today:
            try:
                next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
            except ValueError:
                if birth_month == 2 and birth_day == 29:
                    next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                else:
                    continue

        days_until_birthday = (next_birthday - today).days

        # Send notification for today's birthdays
        if days_until_birthday == 0:
            send_birthday_notifications_to_batchmates.delay(user.id, days_until=0)
            birthday_notifications_sent += 1
        
        # Send notification for upcoming birthdays (3 days before)
        elif days_until_birthday == 3:
            send_birthday_notifications_to_batchmates.delay(user.id, days_until=3)
            upcoming_notifications_sent += 1

    logger.info(
        f"Daily birthday check completed: {birthday_notifications_sent} birthday notifications, "
        f"{upcoming_notifications_sent} upcoming birthday notifications"
    )
    
    return {
        'date': today.isoformat(),
        'birthday_notifications_sent': birthday_notifications_sent,
        'upcoming_notifications_sent': upcoming_notifications_sent
    }


@shared_task
def send_manual_birthday_notification(birthday_user_id):
    """
    Manual task to send birthday notification for a specific user.
    Can be triggered manually from the admin or API.
    """
    return send_birthday_notifications_to_batchmates.delay(birthday_user_id, days_until=0)
