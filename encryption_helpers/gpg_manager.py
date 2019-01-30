from django.conf import settings
import gnupg
import subprocess
from zipfile import ZipFile


class GPGManager:
    def __init__(self):
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
        )


class KeyManager(GPGManager):
    def __init__(self):
        super().__init__()

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
        self.trust_keys([key.fingerprint], 'TRUST_FULLY')

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

        return delete_status

    def trust_keys(self, fingerprints, trust_level):
        # fingerprints is a list of fingerprints of keys for which the trust level is to be set.
        # trust levels are TRUST_UNDEFINED', 'TRUST_NEVER', 'TRUST_MARGINAL', 'TRUST_FULLY' or 'TRUST_ULTIMATE'.
        self.gpg.trust_keys(fingerprints, trust_level)

    def generate_master_keypair(self, name, email, passphrase):
        key = self.create_key(name, email, passphrase)
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

    def __init__(self):
        super().__init__()

        try:
            self.master_fingerprint = settings.GNUPG_MASTER_FINGERPRINT
            if not self.master_fingerprint:
                raise ValueError('GNUPG_MASTER_FINGERPRINT has not been set')
        except django.core.exceptions.ImproperlyConfigured:
            raise ValueError('GNUPG_MASTER_FINGERPRINT has not been set')

    def secure_remove(self, file):
        secure_rm = subprocess.check_call(['srm', '-s', file])
        if secure_rm != 0:
            raise EnvironmentError('srm failed to securely erase the original plaintext file')       

    def encrypt(self, file, recipients):
        if self.master_fingerprint not in recipients:
            self.secure_remove(file)
            raise ValueError('master key fingerprint is not present in list of recipients')

        with open(file, 'rb') as file_stream:
            encryted_data = self.gpg.encrypt_file(file_stream, recipients)
        with open(f'{file}.gpg','w') as document:
            document.write(encryted_data)

        self.secure_remove(file)

        return f'{file}.gpg'

    def encrypt_zip(self, files, archive_name, recipients):
        with ZipFile(archive_name, mode='w') as archive:
            for file in files:
                archive.write(file)
        
        return self.encrypt(archive_name, recipients)
