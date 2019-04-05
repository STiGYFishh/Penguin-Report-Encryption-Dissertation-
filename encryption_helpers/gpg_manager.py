from django.conf import settings
from django.core.files.base import ContentFile
from django.core.exceptions import ImproperlyConfigured

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

import hashlib
import subprocess

from core.encryption_helpers import gnupg
from core.models import PGPKey, Document, DocumentType

import os
import uuid


class GPGManager:
    def __init__(self, uuid):
        self.uuid = uuid

        try:
            self.gnupg_home = settings.GNUPG_HOME
        except django.core.exceptions.ImproperlyConfigured:
            raise ValueError('GNUPG_HOME not set in Django project settings.')

        try:
            self.gnupg_keyring = settings.GNUPG_KEYRING
        except django.core.exceptions.ImproperlyConfigured:
            self.gnupg_keyring = None

        self.gpg = gnupg.GPG(
            gnupghome=self.gnupg_home,
            keyring=self.gnupg_keyring,
            logger_name = self.uuid
        )


class KeyManager(GPGManager):
    def __init__(self, uuid):
        super().__init__(uuid)


    def create_key(self, name, email, passphrase):
        key = self.gpg.gen_key(
            self.gpg.gen_key_input(
                name_real=name,
                name_email=email,
                passphrase=passphrase,
                key_type='RSA',
                key_length=2048,
            )
        )
        self.trust_keys(key.fingerprint, 'TRUST_FULLY')

        return key

    def export_key(self, key, passphrase):
        public_key = self.gpg.export_keys(key.fingerprint)
        private_key = self.gpg.export_keys(
            keyids=key.fingerprint,
            secret=True,
            passphrase=passphrase
        )

        return {'public': public_key, 'private': private_key}

    def delete_key(self, key, delete_public=False):
        # When we cast gnupg.GPG().delete_keys() as a string it will return
        # the resulting status message from the stdout of the gnupg binary.
        # possible returns are 'ok', 'no such key', 'must delete secret key first'.
        delete_status = {'private': None, 'public': None}

        delete_status['private'] = str(
            self.gpg.delete_keys(key.fingerprint, True))

        if delete_public:
            delete_status['public'] = str(self.gpg.delete_keys(key.fingerprint))

        if delete_status != 'ok':
            return {'status':error, 'message':delete_status}

        return {'status':'OK', 'message':delete_status}

    def trust_keys(self, fingerprints, trust_level):
        # fingerprints is a list of fingerprints of keys for which the trust level is to be set.
        # trust levels are TRUST_UNDEFINED', 'TRUST_NEVER', 'TRUST_MARGINAL', 'TRUST_FULLY' or 'TRUST_ULTIMATE'.
        self.gpg.trust_keys(fingerprints, trust_level)

    def generate_master_keypair(self, name, email, passphrase):
        key = self.create_key(name, email, "")
        self.trust_keys([key.fingerprint], 'TRUST_ULTIMATE')

        return key.fingerprint


class EncryptionManager(GPGManager):
    """
    A class to manage the encryption of documents as well as creation of archives.

    All instances of recipients is a list of key fingerprints for those recipients.
    In all cases the application master key fingerprint will be in the list of recipients
    to ensure management of all encrypted files is possible.
    Plaintext files will be removed using srm and the DoD 7 Pass technique.
    """

    def __init__(self, uuid):
        super().__init__(uuid)

        try:
            self.master_fingerprint = settings.GNUPG_MASTER_FINGERPRINT
            if not self.master_fingerprint:
                raise ValueError('GNUPG_MASTER_FINGERPRINT has not been set')
        except ImproperlyConfigured:
            raise ValueError('GNUPG_MASTER_FINGERPRINT has not been set')

    def sha256_checksum(self, data, file=True):
        hasher = hashlib.sha256()

        if file:
            with open(data, 'rb') as stream:
                for chunk in iter(lambda: stream.read(4096), b''):
                    hasher.update(chunk)
        else:
            hasher.update(data.encode())

        return hasher.hexdigest()

    def secure_remove(self, file):
        try:
            secure_rm = subprocess.check_call(['srm', '-s', file])
        except subprocess.CalledProccessError:
            raise EnvironmentError('srm failed to securely erase the original plaintext file')

        return secure_rm

    def encrypt(self, file_uuid):
        document = Document.objects.filter(pk=file_uuid).first()

        if document:
            document_fullpath = os.path.join(settings.MEDIA_ROOT, document.document.name)
            document_path = document.document.name
            document_name = document.document.name.split('/')[-1]

            checksum = self.sha256_checksum(document_fullpath)

            users = []

            groups = document.document_type.groups.all()
            for group in groups:
                for user in group.user_set.all():
                    if user not in users:
                        users.append(user)

            recipients = [self.master_fingerprint]

            if users:
                for user in users:
                    key = PGPKey.objects.filter(created_by=user).first()
                    if key and key.fingerprint:
                        recipients.append(key.fingerprint)


            with open(document_fullpath, 'rb') as file_stream:
                encrypted_data = self.gpg.encrypt_file(file_stream, recipients, always_trust=True)
                if not encrypted_data.ok:
                    layer = get_channel_layer()
                    async_to_sync(layer.send)(
                        'secure-remove',
                        {
                        'type':'remove',
                        'file': document_fullpath,
                        }
                    )
                    return {'status': 'error', 'message':encrypted_data.status}

                file_content = str(encrypted_data)

            file_content = ContentFile(file_content)
            document.document.save(f'{document_name}.gpg', file_content)
            print(f'{document_path}.gpg')
            document.checksum = checksum
            document.save()

            layer = get_channel_layer()
            async_to_sync(layer.send)(
                'secure-remove',
                {
                'type':'remove',
                'file': document_fullpath,
                }
            )

            return {'status':'OK'}
        return {'status': 'error', 'message':'File does not Exist.'}


    def decrypt(self, file_uuid, passphrase):
        document = Document.objects.filter(pk=file_uuid).first()

        if document:
            document_fullpath = os.path.join(settings.MEDIA_ROOT, document.document.name)
            save_path = os.path.join(settings.MEDIA_ROOT, "TMP", str(uuid.uuid4()))

            with open(document_fullpath, 'rb') as encrypted_data:
                decrypted_file = self.gpg.decrypt_file(encrypted_data,
                    passphrase=passphrase,
                    output=save_path
                )

                if not decrypted_file.ok:
                    return {'status': 'error', 'message':document.status}

                if not self.sha256_checksum(save_path) == document.checksum:
                    return {'status': 'error', 'message':'Checksum does not match original file.'}

            return {'status':'OK', 'document':save_path}
        return {'status': 'error', 'message':'File does not Exist.'}


    def re_encrypt(self, file_uuid, passphrase):
        document = Document.objects.filter(pk=file_uuid).first()

        if document:
            decrypted_file = self.decrypt(file_uuid, passphrase)

            if decrypted_file['status'] == 'OK':
                decrypted_file = decrypted_file['document']
                file_content = ContentFile(decrypted_file)

                document.document.save(f'{document.title}', file_content)
                document.save()

            else:
                return decrypted_file

            encrypted_data = self.encrypt(file_uuid)
            del decrypted_file

            if not encrypted_data['status'] == 'OK':
                return {'status': False, 'message':encryted_data}

            return {'status':True}
        return {'status': 'error', 'message':'File does not Exist.'}
