# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAuthToken',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('encrypted_seed', models.CharField(max_length=120)),
                ('type', models.PositiveSmallIntegerField(default=1, choices=[(1, b'Time based (TOTP)'), (2, b'Counter based (HOTP)')])),
                ('counter', models.PositiveIntegerField(default=0)),
                ('created_datetime', models.DateTimeField(auto_now_add=True, verbose_name=b'created')),
                ('updated_datetime', models.DateTimeField(auto_now=True, verbose_name=b'last updated')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
