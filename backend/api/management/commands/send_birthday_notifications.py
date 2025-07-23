from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from api.tasks import send_daily_birthday_notifications, send_birthday_notifications_to_batchmates

User = get_user_model()


class Command(BaseCommand):
    help = 'Send birthday notifications to batchmates'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user-id',
            type=int,
            help='Send birthday notification for a specific user ID',
        )
        parser.add_argument(
            '--all-today',
            action='store_true',
            help='Send notifications for all users with birthdays today',
        )
        parser.add_argument(
            '--upcoming',
            action='store_true',
            help='Send notifications for upcoming birthdays (3 days)',
        )
        parser.add_argument(
            '--daily-check',
            action='store_true',
            help='Run the daily birthday check (includes today and upcoming)',
        )
        parser.add_argument(
            '--test',
            action='store_true',
            help='Test mode - shows what would be sent without actually sending',
        )

    def handle(self, *args, **options):
        if options['daily_check']:
            self.stdout.write('Running daily birthday check...')
            if options['test']:
                self.test_daily_check()
            else:
                result = send_daily_birthday_notifications.delay()
                self.stdout.write(
                    self.style.SUCCESS(f'Daily birthday check task queued: {result.id}')
                )
        
        elif options['user_id']:
            user_id = options['user_id']
            try:
                user = User.objects.get(id=user_id)
                if not user.date_of_birth:
                    self.stdout.write(
                        self.style.ERROR(f'User {user_id} has no birthday set')
                    )
                    return
                
                if options['test']:
                    self.test_user_notification(user)
                else:
                    result = send_birthday_notifications_to_batchmates.delay(user_id, days_until=0)
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Birthday notification task queued for {user.first_name or user.username}: {result.id}'
                        )
                    )
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'User with ID {user_id} not found')
                )
        
        elif options['all_today']:
            if options['test']:
                self.test_today_birthdays()
            else:
                count = self.send_today_birthdays()
                self.stdout.write(
                    self.style.SUCCESS(f'Queued birthday notifications for {count} users')
                )
        
        elif options['upcoming']:
            if options['test']:
                self.test_upcoming_birthdays()
            else:
                count = self.send_upcoming_birthdays()
                self.stdout.write(
                    self.style.SUCCESS(f'Queued upcoming birthday notifications for {count} users')
                )
        
        else:
            self.stdout.write(
                self.style.ERROR('Please specify one of: --user-id, --all-today, --upcoming, or --daily-check')
            )

    def test_daily_check(self):
        """Test what the daily check would do without sending emails."""
        today = timezone.now().date()
        users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)

        today_birthdays = []
        upcoming_birthdays = []

        for user in users_with_birthdays:
            birth_month = user.date_of_birth.month
            birth_day = user.date_of_birth.day

            try:
                next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
            except ValueError:
                if birth_month == 2 and birth_day == 29:
                    next_birthday = timezone.datetime(today.year, 2, 28).date()
                else:
                    continue

            if next_birthday < today:
                try:
                    next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                    else:
                        continue

            days_until_birthday = (next_birthday - today).days

            if days_until_birthday == 0:
                today_birthdays.append(user)
            elif days_until_birthday == 3:
                upcoming_birthdays.append(user)

        self.stdout.write(f'\n=== DAILY BIRTHDAY CHECK TEST ===')
        self.stdout.write(f'Date: {today}')
        
        self.stdout.write(f'\n🎉 TODAY\'S BIRTHDAYS ({len(today_birthdays)} users):')
        for user in today_birthdays:
            self.stdout.write(f'  - {user.first_name or user.username} ({user.email})')
            self.show_batchmates(user)
        
        self.stdout.write(f'\n🎂 UPCOMING BIRTHDAYS - 3 days ({len(upcoming_birthdays)} users):')
        for user in upcoming_birthdays:
            self.stdout.write(f'  - {user.first_name or user.username} ({user.email})')
            self.show_batchmates(user)

    def test_user_notification(self, user):
        """Test notification for a specific user."""
        self.stdout.write(f'\n=== USER NOTIFICATION TEST ===')
        self.stdout.write(f'Birthday Person: {user.first_name or user.username} ({user.email})')
        self.stdout.write(f'Birthday: {user.date_of_birth}')
        self.show_batchmates(user)

    def test_today_birthdays(self):
        """Test today's birthday notifications."""
        today = timezone.now().date()
        today_birthdays = self.get_today_birthdays()
        
        self.stdout.write(f'\n=== TODAY\'S BIRTHDAYS TEST ===')
        self.stdout.write(f'Date: {today}')
        self.stdout.write(f'Found {len(today_birthdays)} users with birthdays today:')
        
        for user in today_birthdays:
            self.stdout.write(f'\n  - {user.first_name or user.username} ({user.email})')
            self.show_batchmates(user)

    def test_upcoming_birthdays(self):
        """Test upcoming birthday notifications."""
        upcoming_birthdays = self.get_upcoming_birthdays()
        
        self.stdout.write(f'\n=== UPCOMING BIRTHDAYS TEST (3 days) ===')
        self.stdout.write(f'Found {len(upcoming_birthdays)} users with upcoming birthdays:')
        
        for user in upcoming_birthdays:
            self.stdout.write(f'\n  - {user.first_name or user.username} ({user.email})')
            self.show_batchmates(user)

    def show_batchmates(self, birthday_user):
        """Show batchmates for a given user."""
        from django.db.models import Q
        
        # Find batchmates using the same logic as the task
        batchmates_query = Q()
        
        if birthday_user.college_name and birthday_user.passed_out_year:
            batchmates_query |= Q(
                college_name__iexact=birthday_user.college_name,
                passed_out_year=birthday_user.passed_out_year
            )
        
        if birthday_user.college_name and birthday_user.course_end_year:
            batchmates_query |= Q(
                college_name__iexact=birthday_user.college_name,
                course_end_year=birthday_user.course_end_year
            )
        
        if birthday_user.course and birthday_user.passed_out_year:
            batchmates_query |= Q(
                course__iexact=birthday_user.course,
                passed_out_year=birthday_user.passed_out_year
            )
        
        batchmates = User.objects.filter(batchmates_query).exclude(
            id=birthday_user.id
        ).exclude(
            email__isnull=True
        ).exclude(
            email=""
        ).filter(
            is_active=True
        )
        
        self.stdout.write(f'    Batchmates found: {batchmates.count()}')
        for batchmate in batchmates[:5]:  # Show first 5
            self.stdout.write(f'      → {batchmate.first_name or batchmate.username} ({batchmate.email})')
        
        if batchmates.count() > 5:
            self.stdout.write(f'      ... and {batchmates.count() - 5} more')

    def get_today_birthdays(self):
        """Get users with birthdays today."""
        today = timezone.now().date()
        today_birthdays = []
        
        users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)
        for user in users_with_birthdays:
            birth_month = user.date_of_birth.month
            birth_day = user.date_of_birth.day
            
            try:
                next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
            except ValueError:
                if birth_month == 2 and birth_day == 29:
                    next_birthday = timezone.datetime(today.year, 2, 28).date()
                else:
                    continue
            
            if next_birthday < today:
                try:
                    next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                    else:
                        continue
            
            days_until_birthday = (next_birthday - today).days
            if days_until_birthday == 0:
                today_birthdays.append(user)
        
        return today_birthdays

    def get_upcoming_birthdays(self):
        """Get users with birthdays in 3 days."""
        today = timezone.now().date()
        upcoming_birthdays = []
        
        users_with_birthdays = User.objects.exclude(date_of_birth__isnull=True).filter(is_active=True)
        for user in users_with_birthdays:
            birth_month = user.date_of_birth.month
            birth_day = user.date_of_birth.day
            
            try:
                next_birthday = timezone.datetime(today.year, birth_month, birth_day).date()
            except ValueError:
                if birth_month == 2 and birth_day == 29:
                    next_birthday = timezone.datetime(today.year, 2, 28).date()
                else:
                    continue
            
            if next_birthday < today:
                try:
                    next_birthday = timezone.datetime(today.year + 1, birth_month, birth_day).date()
                except ValueError:
                    if birth_month == 2 and birth_day == 29:
                        next_birthday = timezone.datetime(today.year + 1, 2, 28).date()
                    else:
                        continue
            
            days_until_birthday = (next_birthday - today).days
            if days_until_birthday == 3:
                upcoming_birthdays.append(user)
        
        return upcoming_birthdays

    def send_today_birthdays(self):
        """Send notifications for today's birthdays."""
        today_birthdays = self.get_today_birthdays()
        
        for user in today_birthdays:
            send_birthday_notifications_to_batchmates.delay(user.id, days_until=0)
        
        return len(today_birthdays)

    def send_upcoming_birthdays(self):
        """Send notifications for upcoming birthdays."""
        upcoming_birthdays = self.get_upcoming_birthdays()
        
        for user in upcoming_birthdays:
            send_birthday_notifications_to_batchmates.delay(user.id, days_until=3)
        
        return len(upcoming_birthdays)
