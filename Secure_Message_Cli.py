import base64
import hashlib
import pyperclip
from typing import Optional


class ModernEncryptionApp:
    def __init__(self, password: str):
        self.password = password
        self.key = self.derive_key(password)

    def derive_key(self, password: str) -> bytes:
        return hashlib.sha256(password.encode()).digest()

    def xor_encrypt(self, data: bytes) -> bytes:
        return bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])

    def encrypt(self, message: str) -> Optional[str]:
        try:
            encrypted_bytes = self.xor_encrypt(message.encode())
            return base64.b64encode(encrypted_bytes).decode()
        except Exception:
            return None

    def decrypt(self, encrypted_message: str) -> Optional[str]:
        try:
            encrypted_bytes = base64.b64decode(encrypted_message.encode())
            decrypted_bytes = self.xor_encrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception:
            return None


def main():
    print("Secure Message Encryption and Decryption (Interactive CLI)\n")

    # Mode selection
    while True:
        mode = input("Choose mode (encrypt / decrypt): ").strip().lower()
        if mode in ["encrypt", "decrypt"]:
            break
        print("Invalid input. Please type 'encrypt' or 'decrypt'.")


    message = input("\nEnter your message: ").strip()
    if not message:
        print("No message entered. Exiting.")
        return

    # Password input
    password = input("Enter password: ").strip()
    if not password:
        print("No password entered. Exiting.")
        return

    # Process
    crypto = ModernEncryptionApp(password)
    result = crypto.encrypt(message) if mode == "encrypt" else crypto.decrypt(message)

    if result is None:
        print("\nOperation invalid. Check your password or input.")
        return

    # Show result
    print("\nResult:")
    print(result)

    # Save option
    save = input("\nSave result to file? (y/n): ").strip().lower()
    if save == "y":
        filename = input("Enter filename (e.g., result.txt): ").strip()
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(result)
            print(f"Result saved to {filename}")
        except Exception as e:
            print(f"Unable to save file: {e}")



if __name__ == "__main__":
    main()


