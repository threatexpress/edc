# Generated by Django 5.2 on 2025-04-22 14:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('collector', '0019_alter_mitigation_finding_alter_mitigation_reference'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mitigation',
            name='reference',
            field=models.TextField(blank=True, help_text='Optional URL to external documentation.', max_length=500),
        ),
    ]
