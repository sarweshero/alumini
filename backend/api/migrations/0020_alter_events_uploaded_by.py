# Generated by Django 5.2.1 on 2025-06-10 09:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0019_rename_worked_in_customuser_worked_in'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='uploaded_by',
            field=models.CharField(choices=[('Student', 'Student'), ('Staff', 'Staff'), ('Admin', 'Admin'), ('Alumni', 'Alumni')], default='Alumni', max_length=10),
        ),
    ]
