# Generated by Django 5.2.1 on 2025-05-31 17:26

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_rename_worked_in_customuser_worked_in'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customuser',
            old_name='worked_in',
            new_name='Worked_in',
        ),
    ]
