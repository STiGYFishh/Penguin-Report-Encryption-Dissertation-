from django.shortcuts import redirect
from django.conf import settings
from core.models import PGPKey, Document, DocumentType

import uuid


class KeysNotSetMixin(object):

    def has_permissions(self):
        if not self.request.user.is_authenticated:
            return 'NOT_AUTHENTICATED'

        master_fingerprint = getattr(settings, 'GNUPG_MASTER_FINGERPRINT', None)
        super_user = self.request.user.is_superuser
        keys = PGPKey.objects.filter(created_by=self.request.user)

        if not master_fingerprint and not super_user:
            return 'KEY_NOT_SET_NO_PERMISSION'
        elif not master_fingerprint and super_user:
            return 'KEY_NOT_SET_HAS_PERMISSION'

        if not keys:
            return 'USER_KEY_NOT_SET'

        return True

    def dispatch(self, request, *args, **kwargs):
        status = self.has_permissions()

        if status == 'NOT_AUTHENTICATED':
            return redirect('/login')
        elif status == 'KEY_NOT_SET_NO_PERMISSION':
            return redirect('conf/master_keys_not_admin')
        elif status == 'KEY_NOT_SET_HAS_PERMISSION':
            return redirect('conf/master_keys')
        elif status == 'USER_KEY_NOT_SET':
            return redirect('settings/create-key')

        return super().dispatch(request, *args, **kwargs)


class SuperUserRequiredMixin(object):

    def has_permissions(self):
        return self.request.user.is_superuser

    def dispatch(self, request, *args, **kwargs):
        if not self.has_permissions():
            return redirect('/')
        return super().dispatch(request, *args, **kwargs)


class MasterKeysGenerationMixin(object):
    def has_permissions(self):
        master_fingerprint = getattr(settings, 'GNUPG_MASTER_FINGERPRINT', None)

        if self.request.user.is_superuser and master_fingerprint is None:
            return True
        return False

    def dispatch(self, request, *args, **kwargs):
        if not self.has_permissions():
            return redirect('/')
        return super().dispatch(request, *args, **kwargs)


class KeyDataExistsMixin(object):
    def can_create(self):
        if not self.request.user.is_authenticated:
            return False

        if 'key_data' in self.request.session:
            return False

        key = PGPKey.objects.filter(created_by=self.request.user).first()
        if key:
            return False

        return True

    def dispatch(self, request, *args, **kwargs):
        if not self.can_create():
            return redirect('/')

        return super().dispatch(request, *args, **kwargs)


class DocumentAccessMixin(object):
    def can_access(self):
        if not self.request.user.is_authenticated:
            return False

        is_document = isinstance(object, Document)
        is_document_type = isinstance(object, DocumentType)

        if is_document:
            for group in object.document_type.groups.all():
                if group in self.request.user.groups():
                    return True

        if is_document_type:
            for group in object.groups.all():
                if group in self.request.user.groups():
                    return True

        return False

    def dispatch(self, request, *args, **kwargs):
        if not self.can_access():
            return redirect('/')

        return super().dispatch(request, *args, **kwargs)


class PrivateKeyCheckMixin(object):
    def check(self):
        if 'private_unlocked' in self.request.session:
            self.request.session['websocket_uuid'] = str(uuid.uuid4())
            return True
        return False

    def dispatch(self, request, *args, **kwargs):
        if not self.check():
            return redirect('/')

        return super().dispatch(request, *args, **kwargs)
