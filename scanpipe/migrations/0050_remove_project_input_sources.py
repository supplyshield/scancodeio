# Generated by Django 4.2.6 on 2023-11-30 10:33

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0049_input_sources_data"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="project",
            name="input_sources",
        ),
    ]
