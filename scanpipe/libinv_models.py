# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class PackageLicenseAssociation(models.Model):
    package = models.OneToOneField('Packages', models.DO_NOTHING, primary_key=True)  # The composite primary key (package_id, license_id) found, that is not supported. The first column is selected.
    license = models.ForeignKey('LicenseFamily', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'package_license_association'
        unique_together = (('package', 'license'),)


class Images(models.Model):
    name = models.CharField(max_length=100)
    backend_tech = models.CharField(max_length=24, blank=True, null=True)
    account = models.ForeignKey('Accounts', models.DO_NOTHING)
    digest = models.CharField(max_length=72)
    tag = models.CharField(max_length=128, blank=True, null=True)
    commit = models.CharField(max_length=128, blank=True, null=True)
    platform = models.CharField(max_length=24)
    parent_image = models.ForeignKey('self', models.DO_NOTHING, blank=True, null=True)
    base_image = models.ForeignKey('self', models.DO_NOTHING, related_name='images_base_image_set', blank=True, null=True)
    repository = models.ForeignKey('Repositories', models.DO_NOTHING, blank=True, null=True)
    wasp = models.ForeignKey('Wasps', models.DO_NOTHING, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'images'


class Packages(models.Model):
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=150, blank=True, null=True)
    language = models.CharField(max_length=20, blank=True, null=True)
    purl = models.CharField(unique=True, max_length=300, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'packages'


class ImagePackageAssociation(models.Model):
    image = models.OneToOneField(Images, models.DO_NOTHING, primary_key=True)  # The composite primary key (image_id, package_id) found, that is not supported. The first column is selected.
    package = models.ForeignKey(Packages, models.DO_NOTHING)
    metadata = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'image_package_association'
        unique_together = (('image', 'package'),)


class VulnerabilityPackageAssociation(models.Model):
    vulnerability = models.OneToOneField('Vulnerabilities', models.DO_NOTHING, primary_key=True)  # The composite primary key (vulnerability_id, package_id) found, that is not supported. The first column is selected.
    package = models.ForeignKey(Packages, models.DO_NOTHING)
    fix = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'vulnerability_package_association'
        unique_together = (('vulnerability', 'package'),)


class Vulnerabilities(models.Model):
    id = models.CharField(primary_key=True, max_length=50)
    description = models.CharField(max_length=500, blank=True, null=True)
    severity = models.CharField(max_length=10, blank=True, null=True)
    related = models.CharField(max_length=200, blank=True, null=True)
    nvd_cvss_base_score = models.FloatField(db_column='nvd-cvss.base_score', blank=True, null=True)  # Field renamed to remove unsuitable characters.
    nvd_cvss_exploitability_score = models.FloatField(db_column='nvd-cvss.exploitability_score', blank=True, null=True)  # Field renamed to remove unsuitable characters.
    nvd_cvss_impact_score = models.FloatField(db_column='nvd-cvss.impact_score', blank=True, null=True)  # Field renamed to remove unsuitable characters.

    class Meta:
        managed = False
        db_table = 'vulnerabilities'


class LicenseFamily(models.Model):
    name = models.CharField(unique=True, max_length=150, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'license_family'


class Layers(models.Model):
    id = models.CharField(primary_key=True)  # The composite primary key (id, image_id, seq) found, that is not supported. The first column is selected.
    image = models.ForeignKey(Images, models.DO_NOTHING)
    seq = models.IntegerField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'layers'
        unique_together = (('id', 'image', 'seq'),)


class Repositories(models.Model):
    provider = models.CharField(max_length=200)
    org = models.CharField(max_length=200)
    name = models.CharField(max_length=200)
    is_public = models.BooleanField()
    pod = models.CharField(max_length=200, blank=True, null=True)
    subpod = models.CharField(max_length=200, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'repositories'


class Accounts(models.Model):
    id = models.CharField(primary_key=True, max_length=12)
    name = models.CharField(max_length=50, blank=True, null=True)
    type = models.CharField(max_length=10)

    class Meta:
        managed = False
        db_table = 'accounts'


class DeploymentCheckpoints(models.Model):
    active = models.IntegerField()
    checkpoint = models.DateTimeField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'deployment_checkpoints'


class LatestImages(models.Model):
    image = models.OneToOneField(Images, models.DO_NOTHING, primary_key=True)  # The composite primary key (image_id, account_id) found, that is not supported. The first column is selected.
    account = models.ForeignKey(Accounts, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'latest_images'
        unique_together = (('image', 'account'),)


class Secbugs(models.Model):
    id = models.CharField(primary_key=True, max_length=50)
    environment = models.CharField(max_length=20, blank=True, null=True)
    severity = models.CharField(max_length=10, blank=True, null=True)
    description = models.CharField(max_length=500, blank=True, null=True)
    vulnerability_category = models.CharField(max_length=40, blank=True, null=True)
    identified_by = models.CharField(max_length=40, blank=True, null=True)
    company = models.CharField(max_length=20, blank=True, null=True)
    isrisk = models.BooleanField(db_column='isRisk', blank=True, null=True)  # Field name made lowercase.
    pulled_at = models.DateTimeField()
    deleted_at = models.DateTimeField(blank=True, null=True)
    repository = models.ForeignKey(Repositories, models.DO_NOTHING, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'secbugs'


class Wasps(models.Model):
    uuid = models.CharField(unique=True, max_length=36)
    repository = models.ForeignKey(Repositories, models.DO_NOTHING, blank=True, null=True)
    tag = models.CharField(max_length=128, blank=True, null=True)
    commit = models.CharField(max_length=128, blank=True, null=True)
    environment = models.CharField(max_length=128, blank=True, null=True)
    jenkins_url = models.CharField(max_length=256, blank=True, null=True)
    raw_message = models.CharField(max_length=1024)
    ate_successfully = models.BooleanField()
    complaints = models.CharField(max_length=1024, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'wasps'


class SastLobMetadata(models.Model):
    module = models.CharField(max_length=1024)
    sub_module = models.CharField(max_length=1024)
    repository = models.ForeignKey(Repositories, models.DO_NOTHING, blank=True, null=True)
    bugcounts = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'sast_lob_metadata'


class SastResult(models.Model):
    id = models.CharField(primary_key=True, max_length=150)
    lob = models.ForeignKey(SastLobMetadata, models.DO_NOTHING, blank=True, null=True)
    extras = models.TextField(blank=True, null=True)  # This field type is a guess.
    vulnsnippet = models.TextField(blank=True, null=True)
    githubpath = models.CharField(max_length=1024, blank=True, null=True)
    secbugurl = models.CharField(max_length=1024, blank=True, null=True)
    file_path = models.CharField(max_length=1024, blank=True, null=True)
    priority = models.CharField(max_length=20, blank=True, null=True)
    confidence = models.CharField(max_length=20, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    public_initial_point = models.TextField(blank=True, null=True)
    source = models.CharField(max_length=200, blank=True, null=True)
    isactive = models.BooleanField(blank=True, null=True)
    wasp = models.ForeignKey(Wasps, models.DO_NOTHING, blank=True, null=True)
    fixed_date = models.DateTimeField(blank=True, null=True)
    validated = models.IntegerField(blank=True, null=True)
    validate_date = models.DateTimeField(blank=True, null=True)
    secbug_created_date = models.DateTimeField(blank=True, null=True)
    mean_solve_time = models.IntegerField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'sast_result'


class CompanyPackages(models.Model):
    purl = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'company_packages'


class ScanpipeVulnerablepaths(models.Model):
    repository_id = models.IntegerField()
    path = models.JSONField()
    action_item = models.IntegerField(blank=True, null=True)
    project_name = models.CharField(max_length=255)
    has_commons_in_path = models.BooleanField()
    vulnerable_package_id = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'scanpipe_vulnerablepaths'
