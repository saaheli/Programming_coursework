import unittest
from Secure_Message_Cli import ModernEncryptionApp

class TestModernEncryptionApp(unittest.TestCase):

    def test_derive_key_consistency(self):
        app1 = ModernEncryptionApp("mypassword")
        app2 = ModernEncryptionApp("mypassword")
        self.assertEqual(app1.key, app2.key)
        self.assertEqual(len(app1.key), 32)

    def test_xor_encrypt_symmetry(self):
        app = ModernEncryptionApp("secure123")
        original = b"Hello, World!"
        encrypted = app.xor_encrypt(original)
        decrypted = app.xor_encrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_encrypt_decrypt(self):
        message = "This is a secret"
        password = "topsecret"
        app = ModernEncryptionApp(password)
        encrypted = app.encrypt(message)
        self.assertIsNotNone(encrypted)
        decrypted = app.decrypt(encrypted)
        self.assertEqual(decrypted, message)

    def test_wrong_password_invalid_decryption(self):
        message = "Secret Data"
        correct = ModernEncryptionApp("correctpass")
        wrong = ModernEncryptionApp("wrongpass")
        encrypted = correct.encrypt(message)
        decrypted = wrong.decrypt(encrypted)
        self.assertNotEqual(decrypted, message)

    def test_invalid_base64_input(self):
        app = ModernEncryptionApp("anypass")
        bad_data = "this is not base64"
        result = app.decrypt(bad_data)
        self.assertIsNone(result)

    def test_encrypt_empty_string(self):
        app = ModernEncryptionApp("pass")
        encrypted = app.encrypt("")
        decrypted = app.decrypt(encrypted)
        self.assertEqual(decrypted, "")


if __name__ == "__main__":
    unittest.main()


