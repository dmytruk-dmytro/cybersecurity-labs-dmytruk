import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import base64
import os


# --- БЛОК ЛОГІКИ (BACKEND) ---
class CryptoEngine:
    def __init__(self):
        self.current_key = None

    def generate_key_from_data(self, personal_data: str) -> bytes:
        """
        Генерація 256-бітного ключа на основі даних користувача.
        Використовує SHA-256.
        """
        data_bytes = personal_data.encode('utf-8')
        return hashlib.sha256(data_bytes).digest()

    def _xor_data(self, data: bytes, key: bytes) -> bytes:
        """
        Базовий алгоритм шифрування (XOR).
        Працює симетрично: encrypt(A) -> B, decrypt(B) -> A.
        """
        key_len = len(key)
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)

    def encrypt_text(self, text: str, key: bytes) -> str:
        """Текст -> Bytes -> XOR -> Base64 String"""
        text_bytes = text.encode('utf-8')
        encrypted_bytes = self._xor_data(text_bytes, key)
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt_text(self, b64_text: str, key: bytes) -> str:
        """Base64 String -> Bytes -> XOR -> Text"""
        try:
            encrypted_bytes = base64.b64decode(b64_text)
            decrypted_bytes = self._xor_data(encrypted_bytes, key)
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return None  # Помилка декодування

    def process_file(self, file_path: str, key: bytes, mode='encrypt'):
        """Шифрування/Дешифрування файлів"""
        with open(file_path, 'rb') as f:
            file_data = f.read()

        processed_data = self._xor_data(file_data, key)

        if mode == 'encrypt':
            out_path = file_path + ".enc"
        else:
            # Спробуємо прибрати .enc, якщо є
            if file_path.endswith(".enc"):
                out_path = file_path[:-4]
            else:
                out_path = file_path + ".decrypted"

        with open(out_path, 'wb') as f:
            f.write(processed_data)

        return out_path


# --- БЛОК ІНТЕРФЕЙСУ (FRONTEND) ---
class SecureMailApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ЛР5: Email Шифратор | Дмитрук Д.А.")
        self.root.geometry("750x600")

        self.engine = CryptoEngine()
        self.key = None  # Поточний ключ у пам'яті

        # Змінні інтерфейсу
        self.name_var = tk.StringVar(value="Dmytruk Dmytro")
        self.dob_var = tk.StringVar(value="19.05.2004")
        self.secret_var = tk.StringVar()

        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Вкладки
        tab_control = ttk.Notebook(self.root)

        self.tab_key = ttk.Frame(tab_control)
        self.tab_msg = ttk.Frame(tab_control)
        self.tab_file = ttk.Frame(tab_control)

        tab_control.add(self.tab_key, text='1. Управління ключем')
        tab_control.add(self.tab_msg, text='2. Повідомлення')
        tab_control.add(self.tab_file, text='3. Файли')

        tab_control.pack(expand=1, fill="both", padx=5, pady=5)

        self._init_tab_key()
        self._init_tab_msg()
        self._init_tab_file()

        # Консоль логів (як у ЛР4)
        log_frame = ttk.LabelFrame(self.root, text="Журнал операцій", padding=5)
        log_frame.pack(fill="x", padx=10, pady=5)
        self.log_text = tk.Text(log_frame, height=6, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 9))
        self.log_text.pack(fill="both")

    def log(self, msg):
        self.log_text.insert(tk.END, f">> {msg}\n")
        self.log_text.see(tk.END)

    def _init_tab_key(self):
        frame = ttk.LabelFrame(self.tab_key, text="Генерація персонального ключа", padding=15)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text="ПІБ:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.name_var, width=30).grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="Дата народження:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.dob_var, width=30).grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Секретна фраза:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.secret_var, show="*", width=30).grid(row=2, column=1, pady=5)

        ttk.Button(frame, text="🔐 ЗГЕНЕРУВАТИ КЛЮЧ", command=self.generate_key).grid(row=3, column=0, columnspan=2,
                                                                                     pady=20, sticky="ew")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
        ttk.Button(btn_frame, text="Зберегти у файл", command=self.save_key).pack(side="left", expand=True, fill="x",
                                                                                  padx=2)
        ttk.Button(btn_frame, text="Завантажити з файлу", command=self.load_key).pack(side="left", expand=True,
                                                                                      fill="x", padx=2)

    def _init_tab_msg(self):
        frame = ttk.Frame(self.tab_msg, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Текст повідомлення або шифр (Base64):").pack(anchor="w")
        self.text_area = tk.Text(frame, height=10, width=60)
        self.text_area.pack(fill="both", expand=True, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Вставити з буфера", command=lambda: self.paste_text(self.text_area)).pack(
            side="right")

        action_frame = ttk.Frame(frame)
        action_frame.pack(fill="x", pady=10)
        ttk.Button(action_frame, text="🔒 ЗАШИФРУВАТИ", command=self.encrypt_msg).pack(side="left", expand=True,
                                                                                      fill="x", padx=5)
        ttk.Button(action_frame, text="🔓 РОЗШИФРУВАТИ", command=self.decrypt_msg).pack(side="right", expand=True,
                                                                                       fill="x", padx=5)

        ttk.Label(frame, text="Результат:").pack(anchor="w")
        self.res_area = tk.Text(frame, height=6, width=60, bg="#f0f0f0")
        self.res_area.pack(fill="both", expand=True, pady=5)

        ttk.Button(frame, text="Копіювати результат", command=lambda: self.copy_text(self.res_area)).pack(anchor="e")

    def _init_tab_file(self):
        frame = ttk.Frame(self.tab_file, padding=20)
        frame.pack(fill="both", expand=True)

        self.file_path = tk.StringVar()
        ttk.Entry(frame, textvariable=self.file_path).pack(fill="x", pady=5)
        ttk.Button(frame, text="Обрати файл", command=self.select_file).pack(pady=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=20)

        ttk.Button(frame, text="Зашифрувати файл (.enc)", command=lambda: self.file_action('encrypt')).pack(fill="x",
                                                                                                            pady=5)
        ttk.Button(frame, text="Розшифрувати файл", command=lambda: self.file_action('decrypt')).pack(fill="x", pady=5)

    # --- ЛОГІКА ІНТЕРФЕЙСУ ---
    def generate_key(self):
        data = self.name_var.get() + self.dob_var.get() + self.secret_var.get()
        if not data:
            messagebox.showerror("Помилка", "Заповніть всі поля!")
            return

        self.key = self.engine.generate_key_from_data(data)
        self.log(f"Ключ згенеровано для: {self.name_var.get()}")
        self.log(f"Хеш ключа (перші байти): {self.key.hex()[:16]}...")
        messagebox.showinfo("Успіх", "Ключ успішно згенеровано!")

    def encrypt_msg(self):
        if not self.key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ!")
            return
        text = self.text_area.get("1.0", tk.END).strip()
        if not text: return

        res = self.engine.encrypt_text(text, self.key)
        self.res_area.delete("1.0", tk.END)
        self.res_area.insert("1.0", res)
        self.log("Повідомлення зашифровано (Base64).")

    def decrypt_msg(self):
        if not self.key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ!")
            return
        cipher = self.text_area.get("1.0", tk.END).strip()
        if not cipher: return

        res = self.engine.decrypt_text(cipher, self.key)
        self.res_area.delete("1.0", tk.END)
        if res:
            self.res_area.insert("1.0", res)
            self.log("Повідомлення успішно розшифровано.")
        else:
            self.res_area.insert("1.0", "ПОМИЛКА: Невірний ключ або пошкоджені дані")
            self.log("Помилка дешифрування!")

    def select_file(self):
        p = filedialog.askopenfilename()
        if p: self.file_path.set(p)

    def file_action(self, mode):
        if not self.key:
            messagebox.showerror("Помилка", "Немає ключа!")
            return
        path = self.file_path.get()
        if not os.path.exists(path): return

        try:
            out = self.engine.process_file(path, self.key, mode)
            self.log(f"Файл оброблено ({mode}): {os.path.basename(out)}")
            messagebox.showinfo("Успіх", f"Файл збережено:\n{os.path.basename(out)}")
        except Exception as e:
            self.log(f"Помилка файлу: {e}")

    def save_key(self):
        if not self.key: return
        p = filedialog.asksaveasfilename(defaultextension=".key")
        if p:
            with open(p, 'wb') as f: f.write(self.key)
            self.log(f"Ключ збережено у файл: {os.path.basename(p)}")

    def load_key(self):
        p = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if p:
            with open(p, 'rb') as f: self.key = f.read()
            self.log(f"Ключ завантажено: {os.path.basename(p)}")
            messagebox.showinfo("Інфо", "Ключ завантажено з файлу!")

    def copy_text(self, widget):
        self.root.clipboard_clear()
        self.root.clipboard_append(widget.get("1.0", tk.END).strip())
        self.log("Результат скопійовано в буфер.")

    def paste_text(self, widget):
        try:
            text = self.root.clipboard_get()
            widget.delete("1.0", tk.END)
            widget.insert("1.0", text)
        except:
            pass


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMailApp(root)
    root.mainloop()