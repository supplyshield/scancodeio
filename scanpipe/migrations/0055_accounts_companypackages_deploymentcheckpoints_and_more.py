# Generated by Django 4.2.6 on 2024-07-22 11:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0054_alter_vulnerablepaths_vulnerable_package_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="Accounts",
            fields=[
                (
                    "id",
                    models.CharField(max_length=12, primary_key=True, serialize=False),
                ),
                ("name", models.CharField(blank=True, max_length=50, null=True)),
                ("type", models.CharField(max_length=10)),
            ],
            options={
                "db_table": "accounts",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="CompanyPackages",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("purl", models.TextField(blank=True, null=True)),
            ],
            options={
                "db_table": "company_packages",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="DeploymentCheckpoints",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("active", models.IntegerField()),
                ("checkpoint", models.DateTimeField()),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "deployment_checkpoints",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Images",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100)),
                (
                    "backend_tech",
                    models.CharField(blank=True, max_length=24, null=True),
                ),
                ("digest", models.CharField(max_length=72)),
                ("tag", models.CharField(blank=True, max_length=128, null=True)),
                ("commit", models.CharField(blank=True, max_length=128, null=True)),
                ("platform", models.CharField(max_length=24)),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "images",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Layers",
            fields=[
                ("id", models.CharField(primary_key=True, serialize=False)),
                ("seq", models.IntegerField()),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "layers",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="LicenseFamily",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        blank=True, max_length=150, null=True, unique=True
                    ),
                ),
            ],
            options={
                "db_table": "license_family",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Packages",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100)),
                ("version", models.CharField(blank=True, max_length=150, null=True)),
                ("language", models.CharField(blank=True, max_length=20, null=True)),
                (
                    "purl",
                    models.CharField(
                        blank=True, max_length=300, null=True, unique=True
                    ),
                ),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "packages",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Repositories",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("provider", models.CharField(max_length=200)),
                ("org", models.CharField(max_length=200)),
                ("name", models.CharField(max_length=200)),
                ("is_public", models.BooleanField()),
                ("pod", models.CharField(blank=True, max_length=200, null=True)),
                ("subpod", models.CharField(blank=True, max_length=200, null=True)),
            ],
            options={
                "db_table": "repositories",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="SastLobMetadata",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("module", models.CharField(max_length=1024)),
                ("sub_module", models.CharField(max_length=1024)),
                ("bugcounts", models.IntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "sast_lob_metadata",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="SastResult",
            fields=[
                (
                    "id",
                    models.CharField(max_length=150, primary_key=True, serialize=False),
                ),
                ("extras", models.TextField(blank=True, null=True)),
                ("vulnsnippet", models.TextField(blank=True, null=True)),
                (
                    "githubpath",
                    models.CharField(blank=True, max_length=1024, null=True),
                ),
                ("secbugurl", models.CharField(blank=True, max_length=1024, null=True)),
                ("file_path", models.CharField(blank=True, max_length=1024, null=True)),
                ("priority", models.CharField(blank=True, max_length=20, null=True)),
                ("confidence", models.CharField(blank=True, max_length=20, null=True)),
                ("description", models.TextField(blank=True, null=True)),
                ("public_initial_point", models.TextField(blank=True, null=True)),
                ("source", models.CharField(blank=True, max_length=200, null=True)),
                ("isactive", models.BooleanField(blank=True, null=True)),
                ("fixed_date", models.DateTimeField(blank=True, null=True)),
                ("validated", models.IntegerField(blank=True, null=True)),
                ("validate_date", models.DateTimeField(blank=True, null=True)),
                ("secbug_created_date", models.DateTimeField(blank=True, null=True)),
                ("mean_solve_time", models.IntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "sast_result",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="ScanpipeVulnerablepaths",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("repository_id", models.IntegerField()),
                ("path", models.JSONField()),
                ("action_item", models.IntegerField(blank=True, null=True)),
                ("project_name", models.CharField(max_length=255)),
                ("has_commons_in_path", models.BooleanField()),
                ("vulnerable_package_id", models.IntegerField(blank=True, null=True)),
            ],
            options={
                "db_table": "scanpipe_vulnerablepaths",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Secbugs",
            fields=[
                (
                    "id",
                    models.CharField(max_length=50, primary_key=True, serialize=False),
                ),
                ("environment", models.CharField(blank=True, max_length=20, null=True)),
                ("severity", models.CharField(blank=True, max_length=10, null=True)),
                (
                    "description",
                    models.CharField(blank=True, max_length=500, null=True),
                ),
                (
                    "vulnerability_category",
                    models.CharField(blank=True, max_length=40, null=True),
                ),
                (
                    "identified_by",
                    models.CharField(blank=True, max_length=40, null=True),
                ),
                ("company", models.CharField(blank=True, max_length=20, null=True)),
                (
                    "isrisk",
                    models.BooleanField(blank=True, db_column="isRisk", null=True),
                ),
                ("pulled_at", models.DateTimeField()),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "secbugs",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Vulnerabilities",
            fields=[
                (
                    "id",
                    models.CharField(max_length=50, primary_key=True, serialize=False),
                ),
                (
                    "description",
                    models.CharField(blank=True, max_length=500, null=True),
                ),
                ("severity", models.CharField(blank=True, max_length=10, null=True)),
                ("related", models.CharField(blank=True, max_length=200, null=True)),
                (
                    "nvd_cvss_base_score",
                    models.FloatField(
                        blank=True, db_column="nvd-cvss.base_score", null=True
                    ),
                ),
                (
                    "nvd_cvss_exploitability_score",
                    models.FloatField(
                        blank=True, db_column="nvd-cvss.exploitability_score", null=True
                    ),
                ),
                (
                    "nvd_cvss_impact_score",
                    models.FloatField(
                        blank=True, db_column="nvd-cvss.impact_score", null=True
                    ),
                ),
            ],
            options={
                "db_table": "vulnerabilities",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="Wasps",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("uuid", models.CharField(max_length=36, unique=True)),
                ("tag", models.CharField(blank=True, max_length=128, null=True)),
                ("commit", models.CharField(blank=True, max_length=128, null=True)),
                (
                    "environment",
                    models.CharField(blank=True, max_length=128, null=True),
                ),
                (
                    "jenkins_url",
                    models.CharField(blank=True, max_length=256, null=True),
                ),
                ("raw_message", models.CharField(max_length=1024)),
                ("ate_successfully", models.BooleanField()),
                (
                    "complaints",
                    models.CharField(blank=True, max_length=1024, null=True),
                ),
                ("created_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "db_table": "wasps",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="ImagePackageAssociation",
            fields=[
                (
                    "image",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        primary_key=True,
                        serialize=False,
                        to="scanpipe.images",
                    ),
                ),
                ("metadata", models.TextField(blank=True, null=True)),
            ],
            options={
                "db_table": "image_package_association",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="LatestImages",
            fields=[
                (
                    "image",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        primary_key=True,
                        serialize=False,
                        to="scanpipe.images",
                    ),
                ),
            ],
            options={
                "db_table": "latest_images",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="PackageLicenseAssociation",
            fields=[
                (
                    "package",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        primary_key=True,
                        serialize=False,
                        to="scanpipe.packages",
                    ),
                ),
            ],
            options={
                "db_table": "package_license_association",
                "managed": False,
            },
        ),
        migrations.CreateModel(
            name="VulnerabilityPackageAssociation",
            fields=[
                (
                    "vulnerability",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        primary_key=True,
                        serialize=False,
                        to="scanpipe.vulnerabilities",
                    ),
                ),
                ("fix", models.CharField(blank=True, max_length=100, null=True)),
            ],
            options={
                "db_table": "vulnerability_package_association",
                "managed": False,
            },
        ),
        migrations.AddField(
            model_name="project",
            name="wasp_uuid",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="scanpipe.wasps",
                to_field="uuid",
            ),
        ),
    ]
