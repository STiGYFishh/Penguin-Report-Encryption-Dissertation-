from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.urls import reverse

from datetime import datetime, timedelta
import uuid

user_model = get_user_model()


def get_sentinel_user():
    return get_user_model().objects.get_or_create(username='deleted')[0]


class PGPKey(models.Model):
    key_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fingerprint = models.CharField(max_length=128, default="NOT_SET")
    realname = models.CharField(max_length=128)
    email = models.EmailField(max_length=256, unique=True)
    password = models.CharField(max_length=256)
    created_by = models.ForeignKey(user_model, on_delete=models.SET(get_sentinel_user))
    created_date = models.DateTimeField(default=timezone.now)
    expire_date = models.DateTimeField(default=datetime.now() + timedelta(days=90))

    class Meta:
        db_table = 'pgp_keys'
        verbose_name_plural = 'pgp_keys'

    def __str__(self):
        """Return fingerprint when cast as string."""
        return self.fingerprint

    def save(self, *args, **kwargs):
        self.password = make_password(self.password)

        super().save(*args, **kwargs)


class DocumentType(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=128, unique=True)

    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        related_name="document_type_set",
        related_query_name="document_type",
    )

    created_by = models.ForeignKey(user_model, blank=True, null=True, on_delete=models.SET(get_sentinel_user))
    created_date = models.DateTimeField(default=timezone.now)


class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=128, unique=True)
    document = models.FileField(upload_to='documents/', null=True)
    checksum = models.CharField(max_length=128, blank=True, null=True)
    document_type = models.ForeignKey(DocumentType, blank=True, null=True, on_delete=models.SET_NULL)
    created_by = models.ForeignKey(user_model, blank=True, null=True, on_delete=models.SET(get_sentinel_user))
    created_date = models.DateTimeField(default=timezone.now)
