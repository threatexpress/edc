# Generated by Django 5.2 on 2025-04-17 13:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('collector', '0009_exfilfile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='oplogentry',
            name='exfil',
        ),
    ]
