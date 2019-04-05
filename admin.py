from django.contrib import admin

from core.models import PGPKey, Document, DocumentType
# Register your models here.
admin.site.register(PGPKey)
admin.site.register(DocumentType)
admin.site.register(Document)
