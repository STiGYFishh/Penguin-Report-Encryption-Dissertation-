from django.test import TestCase
from django.core.files.base import ContentFile

from core.models import Document, DocumentType
from core.encryption_helpers.gpg_manager import EncryptionManager


class EncryptionTestCase(TestCase):
    def setUp(self):
        document_type = DocumentType.objects.create(name="Test")
        document = Document.objects.create(
            title="test_file.txt", document_type=document_type)

        test_file = ContentFile("test_data")
        document.document.save("test_file.txt", test_file)
        document.save()

        self.document_id = str(document.id)

    def test_file_encryption(self):
        manager = EncryptionManager(self.document_id)

        result = manager.encrypt(self.document_id)

        self.assertEqual(result['status'], "OK")


class DecryptionTestCase(TestCase):
    def setUp(self):
        document_type = DocumentType.objects.create(name="Test")
        document = Document.objects.create(
            title="test_file.txt", document_type=document_type)

        test_file = ContentFile("test_data")
        document.document.save("test_file.txt", test_file)
        document.save()

        self.document_id = str(document.id)
        self.manager = EncryptionManager(self.document_id)

        self.manager.encrypt(self.document_id)

    def test_file_decryption(self):
        result = self.manager.decrypt(self.document_id, "password")

        self.assertEqual(result['status'], "OK")


class ReEncryptionTestCase(TestCase):
    def setUp(self):
        document_type = DocumentType.objects.create(name="Test")
        document = Document.objects.create(
            title="test_file.txt", document_type=document_type)

        test_file = ContentFile("test_data")
        document.document.save("test_file.txt", test_file)
        document.save()

        self.document_id = str(document.id)
        self.manager = EncryptionManager(self.document_id)

        self.manager.encrypt(self.document_id)

    def test_file_re_encryption(self):
        result = self.manager.re_encrypt(self.document_id, "password")

        self.assertEqual(result['status'], True)
