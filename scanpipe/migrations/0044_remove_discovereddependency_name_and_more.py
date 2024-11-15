# Generated by Django 4.2.4 on 2023-08-28 09:47

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0043_delete_projecterror"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="discovereddependency",
            name="name",
        ),
        migrations.RemoveField(
            model_name="discovereddependency",
            name="namespace",
        ),
        migrations.RemoveField(
            model_name="discovereddependency",
            name="qualifiers",
        ),
        migrations.RemoveField(
            model_name="discovereddependency",
            name="subpath",
        ),
        migrations.RemoveField(
            model_name="discovereddependency",
            name="type",
        ),
        migrations.RemoveField(
            model_name="discovereddependency",
            name="version",
        ),
        migrations.AddField(
            model_name="discovereddependency",
            name="package",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="dependents",
                to="scanpipe.discoveredpackage",
            ),
        ),
    ]
