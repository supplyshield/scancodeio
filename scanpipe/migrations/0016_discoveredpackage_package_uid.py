# Generated by Django 4.0.4 on 2022-06-09 18:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0015_alter_codebaseresource_project_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='discoveredpackage',
            name='package_uid',
            field=models.CharField(blank=True, help_text='Unique identifier for this package.', max_length=1024),
        ),
    ]
