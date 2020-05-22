# Generated by Django 2.2.6 on 2019-10-31 18:51

import django.core.files.storage
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('edc', '0006_auto_20191031_1845'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cred',
            name='tknfile',
            field=models.FileField(blank=True, null=True, storage=django.core.files.storage.FileSystemStorage(base_url='/protected', location='/var/www/edc_app/protected'), upload_to=''),
        ),
        migrations.AlterField(
            model_name='oplog',
            name='exfil',
            field=models.FileField(blank=True, null=True, storage=django.core.files.storage.FileSystemStorage(base_url='/protected', location='/var/www/edc_app/protected'), upload_to=''),
        ),
        migrations.AlterField(
            model_name='oplog',
            name='scrsht',
            field=models.FileField(blank=True, null=True, storage=django.core.files.storage.FileSystemStorage(base_url='/protected', location='/var/www/edc_app/protected'), upload_to=''),
        ),
    ]