# Generated by Django 4.2.6 on 2024-07-16 05:39

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0053_alter_vulnerablepaths_action_item"),
    ]

    operations = [
        migrations.AlterField(
            model_name="vulnerablepaths",
            name="vulnerable_package_id",
            field=models.IntegerField(null=True),
        ),
    ]
