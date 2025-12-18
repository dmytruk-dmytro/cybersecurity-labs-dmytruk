import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
import hashlib
import os


# Блок математики RSA
class RSAEngine:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def is_prime(self, n, k=5):
        """Тест Міллера-Рабіна на простоту"""
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits):
        """Генерує просте число заданої бітності"""
        while True:
            # Генеруємо непарне число
            num = random.getrandbits(bits)
            if num % 2 == 0:
                num += 1
            if self.is_prime(num):
                return num

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        d, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return d, x, y

    def mod_inverse(self, e, phi):
        d, x, y = self.extended_gcd(e, phi)
        if d != 1:
            raise Exception("Оберненого елемента не існує")
        return x % phi

    def generate_keys(self, seed_data, key_size=512):
        """
        Генерація ключів на основі персональних даних (seed_data).
        """
        # Ініціалізуємо генератор випадкових чисел хешем від даних студента
        seed_hash = hashlib.sha256(seed_data.encode()).digest()
        seed_int = int.from_bytes(seed_hash, 'big')
        random.seed(seed_int)

        p = self.generate_prime(key_size // 2)
        q = self.generate_prime(key_size // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        # Перевірка на взаємну простоту
        while self.gcd(e, phi) != 1:
            e += 2

        d = self.mod_inverse(e, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)

        # Скидаємо seed для безпеки подальших операцій
        random.seed()
        return self.public_key, self.private_key

    def sign_hash(self, data_hash, d, n):
        """Підпис: H^d mod n"""
        hash_int = int.from_bytes(data_hash, 'big')
        signature_int = pow(hash_int, d, n)
        return signature_int

    def verify_hash(self, signature_int, e, n):
        """Перевірка: S^e mod n -> повинен вийти хеш"""
        hash_int = pow(signature_int, e, n)
        return hash_int


# Блок інтерфейсу
class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ЛР4: Цифровий Підпис | Дмитрук Д.А.")
        self.root.geometry("700x550")
        self.rsa = RSAEngine()

        # Стилізація
        style = ttk.Style()
        style.theme_use('clam')

        # Змінні
        self.name_var = tk.StringVar(value="Dmytruk Dmytro")
        self.dob_var = tk.StringVar(value="19.05.2004")
        self.file_path_var = tk.StringVar()
        self.sig_path_var = tk.StringVar()

        self.setup_ui()

    def setup_ui(self):
        # Фрейм генерації ключів
        gen_frame = ttk.LabelFrame(self.root, text="1. Персоналізація та Ключі", padding=10)
        gen_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(gen_frame, text="ПІБ:").grid(row=0, column=0, sticky="w")
        ttk.Entry(gen_frame, textvariable=self.name_var, width=30).grid(row=0, column=1, padx=5)

        ttk.Label(gen_frame, text="Дата народження:").grid(row=0, column=2, sticky="w")
        ttk.Entry(gen_frame, textvariable=self.dob_var, width=15).grid(row=0, column=3, padx=5)

        ttk.Button(gen_frame, text="Згенерувати пару ключів (RSA)", command=self.generate_keys_ui).grid(row=1, column=0,
                                                                                                        columnspan=4,
                                                                                                        pady=10,
                                                                                                        sticky="ew")

        # Фрейм роботи з файлами
        ops_frame = ttk.LabelFrame(self.root, text="2. Операції з документами", padding=10)
        ops_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(ops_frame, text="Файл:").grid(row=0, column=0, sticky="w")
        ttk.Entry(ops_frame, textvariable=self.file_path_var, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(ops_frame, text="Обрати...", command=self.browse_file).grid(row=0, column=2)

        ttk.Button(ops_frame, text="📝 ПІДПИСАТИ ФАЙЛ", command=self.sign_file_ui).grid(row=1, column=0, columnspan=3,
                                                                                       pady=5, sticky="ew")

        ttk.Label(ops_frame, text="Файл підпису (.sig):").grid(row=2, column=0, sticky="w")
        ttk.Entry(ops_frame, textvariable=self.sig_path_var, width=50).grid(row=2, column=1, padx=5)
        ttk.Button(ops_frame, text="Обрати...", command=self.browse_sig).grid(row=2, column=2)

        ttk.Button(ops_frame, text="🔍 ПЕРЕВІРИТИ ПІДПИС", command=self.verify_sig_ui).grid(row=3, column=0,
                                                                                           columnspan=3, pady=5,
                                                                                           sticky="ew")

        # Лог консоль
        log_frame = ttk.LabelFrame(self.root, text="Журнал операцій", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = tk.Text(log_frame, height=10, state='disabled', bg="#2b2b2b", fg="#00ff00",
                                font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f">> {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def generate_keys_ui(self):
        seed = self.name_var.get() + self.dob_var.get()
        if not seed:
            messagebox.showerror("Помилка", "Введіть персональні дані!")
            return

        self.log(f"Генерація RSA ключів для користувача: {self.name_var.get()}...")
        try:
            pub, priv = self.rsa.generate_keys(seed)
            self.log(f"Ключі згенеровано успішно.")
            self.log(f"Публічний ключ (e, n): ({pub[0]}, {str(pub[1])[:10]}...)")

            # Збереження
            with open("my_public.key", "w") as f:
                f.write(f"<RSAKeyValue><Modulus>{pub[1]}</Modulus><Exponent>{pub[0]}</Exponent></RSAKeyValue>")
            with open("my_private.key", "w") as f:
                f.write(f"<RSAKeyValue><Modulus>{priv[1]}</Modulus><D>{priv[0]}</D></RSAKeyValue>")

            messagebox.showinfo("Успіх", "Пару ключів збережено у папці програми.")
        except Exception as e:
            self.log(f"Помилка: {e}")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path: self.file_path_var.set(path)

    def browse_sig(self):
        path = filedialog.askopenfilename(filetypes=[("Signature", "*.sig")])
        if path: self.sig_path_var.set(path)

    def sign_file_ui(self):
        fpath = self.file_path_var.get()
        if not fpath or not os.path.exists(fpath):
            messagebox.showerror("Помилка", "Оберіть файл!")
            return

        if not self.rsa.private_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
            return

        self.log(f"Хешування файлу: {os.path.basename(fpath)} (SHA-256)")

        # Хешування
        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        file_hash = sha256.digest()

        # Підпис
        d, n = self.rsa.private_key
        sig_int = self.rsa.sign_hash(file_hash, d, n)

        # Збереження
        sig_path = fpath + ".sig"
        with open(sig_path, "w") as f:
            f.write(hex(sig_int))

        self.sig_path_var.set(sig_path)
        self.log(f"Файл підписано. Підпис збережено: {os.path.basename(sig_path)}")
        messagebox.showinfo("Успіх", "Файл успішно підписано!")

    def verify_sig_ui(self):
        fpath = self.file_path_var.get()
        spath = self.sig_path_var.get()

        if not fpath or not spath:
            messagebox.showerror("Помилка", "Оберіть файл та файл підпису!")
            return

        self.log("--- Початок верифікації ---")

        # 1. Читаємо хеш файлу
        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        actual_hash_int = int.from_bytes(sha256.digest(), 'big')

        # 2. Читаємо підпис
        try:
            with open(spath, "r") as f:
                sig_int = int(f.read(), 16)
        except:
            self.log("Помилка читання файлу підпису!")
            return

        # 3. Розшифровуємо підпис
        e, n = self.rsa.public_key
        decrypted_hash_int = self.rsa.verify_hash(sig_int, e, n)

        self.log(f"Обчислений хеш (int): {str(actual_hash_int)[:15]}...")
        self.log(f"Хеш з підпису (int):  {str(decrypted_hash_int)[:15]}...")

        if actual_hash_int == decrypted_hash_int:
            self.log("РЕЗУЛЬТАТ: [OK] ПІДПИС ДІЙСНИЙ ✅")
            messagebox.showinfo("Результат", "Підпис ДІЙСНИЙ! Файл не змінено.")
        else:
            self.log("РЕЗУЛЬТАТ: [FAIL] ПІДПИС НЕДІЙСНИЙ ❌")
            messagebox.showwarning("Результат", "УВАГА! Підпис НЕДІЙСНИЙ! Файл було модифіковано.")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()