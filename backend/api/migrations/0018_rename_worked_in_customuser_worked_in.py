# Generated by Django 5.2.1 on 2025-05-31 17:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_remove_newsroom_views'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='Worked_in',
            new_name='worked_in',
        ),
    ]
