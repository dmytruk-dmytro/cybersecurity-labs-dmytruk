import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import time
import os
import struct
import random
from PIL import Image


# Модуль 1: Цифровий підпис (RSA)

class RSAManager:

    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        p = 499
        q = 503
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 17
        # Обчислення d (обернене до e по модулю phi)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            # На випадок якщо e не взаємно просте з phi
            e = 23
            d = pow(e, -1, phi)

        self.public_key = (e, n)
        self.private_key = (d, n)
        return self.public_key, self.private_key

    def sign_data(self, data: bytes) -> bytes:
        if not self.private_key:
            self.generate_keys()

        d, n = self.private_key

        # 1. Хешуємо дані
        data_hash = hashlib.sha256(data).digest()

        # 2. Беремо 2 байти (макс число 65535)
        hash_int = int.from_bytes(data_hash[:2], byteorder='big')

        # 3. Підписуємо
        signature_int = pow(hash_int, d, n)

        # 4. Пакуємо
        sig_bytes = struct.pack('>I', signature_int)
        return sig_bytes + data

    def verify_data(self, data: bytes) -> bytes:
        if not self.public_key:
            self.generate_keys()

        e, n = self.public_key

        try:
            # Розпаковка
            signature_int = struct.unpack('>I', data[:4])[0]
            original_content = data[4:]

            # 1. Рахуємо хеш того, що прийшло
            data_hash = hashlib.sha256(original_content).digest()
            expected_hash_int = int.from_bytes(data_hash[:2], byteorder='big')

            # 2. Розшифровуємо підпис
            decrypted_hash_int = pow(signature_int, e, n)

            # 3. Порівнюємо
            if decrypted_hash_int != expected_hash_int:
                raise ValueError("Підпис RSA НЕВІРНИЙ! (Хеші не зійшлися)")

            return original_content
        except struct.error:
            raise ValueError("Структура даних пошкоджена (можливо, невірний пароль XOR).")


# Модуль 2: Шифрування (XOR)
class XORCipher:
    """
    Потокове шифрування методом гамування.
    Генерує гаму на основі пароля.
    """

    @staticmethod
    def _generate_gamma(seed_str: str, length: int) -> bytes:
        random.seed(seed_str)
        return bytes([random.randint(0, 255) for _ in range(length)])

    @staticmethod
    def encrypt_decrypt(data: bytes, password: str) -> bytes:
        gamma = XORCipher._generate_gamma(password, len(data))
        # XOR операція: Data ^ Gamma
        return bytes([b ^ g for b, g in zip(data, gamma)])


# Модуль 3: Стеганографія (LSB)
class StegoLSB:
    @staticmethod
    def hide_data(image_path, data, output_path):
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        # Заголовок розміру (4 байти)
        full_data = struct.pack('>I', len(data)) + data

        if len(full_data) * 8 > len(pixels) * 3:
            raise ValueError("Файл занадто великий для цієї картинки!")

        bits = []
        for byte in full_data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        new_pixels = []
        bit_idx = 0
        for p in pixels:
            if bit_idx < len(bits):
                r, g, b = p
                if bit_idx < len(bits): r = (r & ~1) | bits[bit_idx]; bit_idx += 1
                if bit_idx < len(bits): g = (g & ~1) | bits[bit_idx]; bit_idx += 1
                if bit_idx < len(bits): b = (b & ~1) | bits[bit_idx]; bit_idx += 1
                new_pixels.append((r, g, b))
            else:
                new_pixels.append(p)

        img.putdata(new_pixels)
        img.save(output_path, "PNG")
        return len(full_data)

    @staticmethod
    def extract_data(image_path):
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        bits = []
        for p in pixels:
            bits.append(p[0] & 1)
            bits.append(p[1] & 1)
            bits.append(p[2] & 1)

        # Функція: масив бітів -> байти
        def bits_to_bytes(bits_arr):
            chars = []
            for i in range(0, len(bits_arr), 8):
                byte = bits_arr[i:i + 8]
                if len(byte) < 8: break
                val = 0
                for bit in byte:
                    val = (val << 1) | bit
                chars.append(val)
            return bytes(chars)

        # Читаємо розмір (перші 32 біти)
        size_bytes = bits_to_bytes(bits[:32])
        data_size = struct.unpack('>I', size_bytes)[0]

        # Читаємо тіло
        total_bits_needed = 32 + (data_size * 8)
        raw_data = bits_to_bytes(bits[32:total_bits_needed])
        return raw_data


# Головний контролер (GUI)

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ЛР7: Комплексний захист | Дмитрук Д.А.")
        self.root.geometry("1000x700")

        self.rsa = RSAManager()
        self.stats = []
        self.file_path = ""
        self.img_path = ""

        style = ttk.Style()
        style.theme_use('clam')

        # Вкладки
        tab_control = ttk.Notebook(root)
        self.tab_protect = ttk.Frame(tab_control)
        self.tab_restore = ttk.Frame(tab_control)
        self.tab_analytics = ttk.Frame(tab_control)

        tab_control.add(self.tab_protect, text='1. Захист (Pipeline)')
        tab_control.add(self.tab_restore, text='2. Відновлення')
        tab_control.add(self.tab_analytics, text='3. Аналітика')
        tab_control.pack(expand=1, fill="both")

        self.setup_protect_tab()
        self.setup_restore_tab()
        self.setup_analytics_tab()

    def log_stat(self, scenario, stage, start_time, size):
        duration = (time.time() - start_time) * 1000
        self.stats.append((scenario, stage, f"{duration:.2f} ms", f"{size} bytes"))
        self.update_analytics_table()

    # Вкладка 1: Захист
    def setup_protect_tab(self):
        frame = ttk.LabelFrame(self.tab_protect, text="Конфігурація", padding=20)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Button(frame, text="1. Обрати файл (документ)", command=self.select_file).pack(fill="x", pady=5)
        self.lbl_file = ttk.Label(frame, text="...", foreground="gray")
        self.lbl_file.pack()

        ttk.Button(frame, text="2. Обрати картинку (контейнер)", command=self.select_img).pack(fill="x", pady=5)
        self.lbl_img = ttk.Label(frame, text="...", foreground="gray")
        self.lbl_img.pack()

        ttk.Label(frame, text="Пароль (для XOR гамування):").pack(pady=5)
        self.entry_pass = ttk.Entry(frame, show="*")
        self.entry_pass.pack(fill="x")
        self.entry_pass.insert(0, "lab_password")

        ttk.Button(frame, text="🚀 ЗАХИСТИТИ (RSA -> XOR -> LSB)", command=self.run_protection).pack(fill="x", pady=15)
        ttk.Button(frame, text="📊 Запустити БЕНЧМАРК", command=self.run_benchmark).pack(fill="x", pady=5)

        self.status_protect = ttk.Label(frame, text="Очікування...", font=("Arial", 10, "bold"))
        self.status_protect.pack(pady=20)

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        self.lbl_file.config(text=os.path.basename(self.file_path))

    def select_img(self):
        self.img_path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        self.lbl_img.config(text=os.path.basename(self.img_path))

    def run_protection(self, is_benchmark=False):
        if not self.file_path or not self.img_path:
            messagebox.showerror("Помилка", "Дані не обрано!")
            return

        pwd = self.entry_pass.get()
        scenario = "Full Protect" if not is_benchmark else "Benchmark Run"

        try:
            # 1. Читання
            ext = os.path.splitext(self.file_path)[1].encode()
            with open(self.file_path, "rb") as f:
                raw = f.read()
            payload = struct.pack('B', len(ext)) + ext + raw

            # 2. RSA Sign (Цілісність)
            t0 = time.time()
            self.rsa.generate_keys()  # Генеруємо ключі для сесії
            signed_data = self.rsa.sign_data(payload)
            self.log_stat(scenario, "Sign (RSA)", t0, len(signed_data))

            # 3. XOR Encrypt (Конфіденційність)
            t0 = time.time()
            encrypted_data = XORCipher.encrypt_decrypt(signed_data, pwd)
            self.log_stat(scenario, "Encrypt (XOR)", t0, len(encrypted_data))

            # 4. LSB Hide (Приховування)
            t0 = time.time()
            out_name = os.path.splitext(self.img_path)[0] + "_protected.png"
            StegoLSB.hide_data(self.img_path, encrypted_data, out_name)
            self.log_stat(scenario, "Hide (LSB)", t0, os.path.getsize(out_name))

            self.status_protect.config(text=f"УСПІХ! Файл: {os.path.basename(out_name)}", foreground="green")
            if not is_benchmark:
                messagebox.showinfo("Готово", "Файл підписано (RSA), зашифровано (XOR) і сховано (LSB)!")

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def run_benchmark(self):
        self.stats = []
        self.update_analytics_table()

        t0 = time.time()
        XORCipher.encrypt_decrypt(b"test" * 500, "pass")
        self.log_stat("1. Only Encryption", "XOR", t0, 2000)

        t0 = time.time()
        self.rsa.generate_keys()
        self.rsa.sign_data(b"test" * 500)
        self.log_stat("2. Sign + Encrypt", "RSA+XOR", t0, 2100)

        self.run_protection(is_benchmark=True)
        messagebox.showinfo("Звіт", "Бенчмарк завершено!")

    # Вкладка 2: Відновлення
    def setup_restore_tab(self):
        frame = ttk.LabelFrame(self.tab_restore, text="Зворотний процес", padding=20)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Button(frame, text="Обрати захищену картинку", command=self.select_protected).pack(fill="x")
        self.lbl_prot = ttk.Label(frame, text="...", foreground="gray")
        self.lbl_prot.pack()

        ttk.Label(frame, text="Пароль:").pack(pady=5)
        self.entry_pass_res = ttk.Entry(frame, show="*")
        self.entry_pass_res.pack(fill="x")

        ttk.Button(frame, text="ВІДНОВИТИ", command=self.run_restore).pack(fill="x", pady=20)
        self.status_res = ttk.Label(frame, text="")
        self.status_res.pack()

    def select_protected(self):
        self.prot_path = filedialog.askopenfilename(filetypes=[("PNG", "*.png")])
        self.lbl_prot.config(text=os.path.basename(self.prot_path))

    def run_restore(self):
        if not hasattr(self, 'prot_path'): return
        pwd = self.entry_pass_res.get()

        try:
            # 1. Розпакування LSB
            data = StegoLSB.extract_data(self.prot_path)
            # 2. XOR розшифрування
            decrypted = XORCipher.encrypt_decrypt(data, pwd)
            # 3. RSA верифікація
            verified_payload = self.rsa.verify_data(decrypted)

            # Збереження
            ext_len = verified_payload[0]
            ext = verified_payload[1:1 + ext_len].decode()
            content = verified_payload[1 + ext_len:]

            out_path = "restored" + ext
            with open(out_path, "wb") as f:
                f.write(content)

            self.status_res.config(text=f"✅ ВІРНО! Відновлено: {out_path}", foreground="green")
            messagebox.showinfo("Успіх", f"Файл відновлено: {out_path}\nЦілісність підтверджено!")
        except Exception as e:
            self.status_res.config(text="ПОМИЛКА! (Підпис невірний)", foreground="red")
            messagebox.showerror("Помилка", str(e))

    # Вкладка 3: Аналітика
    def setup_analytics_tab(self):
        cols = ("Сценарій", "Етап", "Час", "Розмір")
        self.tree = ttk.Treeview(self.tab_analytics, columns=cols, show="headings")
        for c in cols: self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True)
        ttk.Button(self.tab_analytics, text="Експортувати звіт (CSV)", command=self.export_csv).pack(pady=10)

    def update_analytics_table(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for r in self.stats: self.tree.insert("", "end", values=r)

    def export_csv(self):
        with open("lab7_report.csv", "w") as f:
            f.write("Scenario,Stage,Time,Size\n")
            for r in self.stats: f.write(f"{r[0]},{r[1]},{r[2]},{r[3]}\n")
        messagebox.showinfo("Експорт", "Збережено!")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()