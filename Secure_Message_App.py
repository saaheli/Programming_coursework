import base64
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
from typing import Optional


class ModernEncryptionApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Message Encryption and Decryption")
        self.window.geometry("800x700")
        self.window.configure(bg="#f3f4f6")
        self.setup_styles()

        self.main_frame = ttk.Frame(self.window, style="Main.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.create_header()
        self.create_input_area()
        self.create_password_field()
        self.create_action_buttons()
        self.create_utility_buttons()
        self.create_result_area()

    def setup_styles(self):
        style = ttk.Style()
        style.configure("Main.TFrame", background="#ffffff")
        style.configure("Encrypt.TButton", padding=10, background="#ef4444", foreground="black", font=("Helvetica", 12))
        style.map("Encrypt.TButton", background=[("active", "#dc2626")])
        style.configure("Decrypt.TButton", padding=10, background="#22c55e", foreground="black", font=("Helvetica", 12))
        style.map("Decrypt.TButton", background=[("active", "#16a34a")])
        style.configure("Utility.TButton", padding=10, background="#3b82f6", foreground="black", font=("Helvetica", 12))
        style.map("Utility.TButton", background=[("active", "#2563eb")])
        style.configure("Header.TLabel", font=("Helvetica", 24, "bold"), background="#ffffff")
        style.configure("Label.TLabel", font=("Helvetica", 12), background="#ffffff")

    def create_header(self):
        header = ttk.Label(self.main_frame, text="Secure Message Encryption and Decryption", style="Header.TLabel")
        header.pack(pady=(0, 20))

    def create_input_area(self):
        ttk.Label(self.main_frame, text="Enter text for encryption and decryption", style="Label.TLabel").pack(anchor="w", pady=(0, 5))
        self.text_input = tk.Text(self.main_frame, height=10, width=50, font=("Helvetica", 12), wrap=tk.WORD, bd=1, relief="solid")
        self.text_input.pack(fill=tk.X, pady=(0, 20))

    def create_password_field(self):
        ttk.Label(self.main_frame, text="Password", style="Label.TLabel").pack(anchor="w", pady=(0, 5))
        self.password_input = ttk.Entry(self.main_frame, show="•", font=("Helvetica", 12))
        self.password_input.pack(fill=tk.X, pady=(0, 20))

    def create_action_buttons(self):
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))

        encrypt_btn = ttk.Button(button_frame, text="Encrypt", style="Encrypt.TButton", command=self.handle_encryption)
        encrypt_btn.pack(side=tk.LEFT, expand=True, padx=5)

        decrypt_btn = ttk.Button(button_frame, text="Decrypt", style="Decrypt.TButton", command=self.handle_decryption)
        decrypt_btn.pack(side=tk.LEFT, expand=True, padx=5)

    def create_utility_buttons(self):
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))

        open_btn = ttk.Button(button_frame, text="Open File", style="Utility.TButton", command=self.handle_file_open)
        open_btn.pack(side=tk.LEFT, expand=True, padx=5)

        save_btn = ttk.Button(button_frame, text="Save", style="Utility.TButton", command=self.handle_save)
        save_btn.pack(side=tk.LEFT, expand=True, padx=5)

        copy_btn = ttk.Button(button_frame, text="Copy", style="Utility.TButton", command=self.handle_copy)
        copy_btn.pack(side=tk.LEFT, expand=True, padx=5)

    def create_result_area(self):
        self.result_frame = ttk.Frame(self.main_frame)
        self.result_frame.pack(fill=tk.X, pady=(0, 20))
        self.result_frame.pack_forget()
        ttk.Label(self.result_frame, text="Result", style="Label.TLabel").pack(anchor="w", pady=(0, 5))
        self.result_text = tk.Text(self.result_frame, height=4, width=50, font=("Helvetica", 12), wrap=tk.WORD, bd=1, relief="solid", bg="#f3f4f6")
        self.result_text.pack(fill=tk.X)

    def derive_key(self, password: str) -> bytes:
        """Create a key using SHA256 (used for XORing with data)"""
        return hashlib.sha256(password.encode()).digest()

    def xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def encrypt(self, message: str, password: str) -> Optional[str]:
        try:
            key = self.derive_key(password)
            encrypted_bytes = self.xor_encrypt(message.encode(), key)
            return base64.b64encode(encrypted_bytes).decode()
        except Exception:
            return None

    def decrypt(self, encrypted_message: str, password: str) -> Optional[str]:
        try:
            key = self.derive_key(password)
            encrypted_bytes = base64.b64decode(encrypted_message.encode())
            decrypted_bytes = self.xor_encrypt(encrypted_bytes, key)
            return decrypted_bytes.decode()
        except Exception:
            return None

    def handle_encryption(self):
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        result = self.encrypt(message, password)
        if result:
            self.show_result(result)
            messagebox.showinfo("Success", "Text encrypted successfully!")
        else:
            messagebox.showerror("Error", "Encryption failed. Please try again.")

    def handle_decryption(self):
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        result = self.decrypt(message, password)
        if result:
            self.show_result(result)
            messagebox.showinfo("Success", "Text decrypted successfully!")
        else:
            messagebox.showerror("Error", "Decryption failed. Check your password or message.")

    def handle_file_open(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")

    def handle_save(self):
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        encrypted = self.encrypt(message, password)
        if encrypted:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if file_path:
                try:
                    with open(file_path, 'w') as file:
                        file.write(encrypted)
                    messagebox.showinfo("Success", "File saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file: {str(e)}")
        else:
            messagebox.showerror("Error", "Encryption failed.")

    def handle_copy(self):
        result = self.result_text.get("1.0", tk.END).strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Success", "Text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No result to copy!")

    def show_result(self, result: str):
        self.result_frame.pack(fill=tk.X, pady=(0, 20))
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)

    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = ModernEncryptionApp()
    app.run()


