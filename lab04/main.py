import hashlib
import random
import os
import sys

class FileDigitalSignature:
    def __init__(self):
        self.public_key = None
        self.__private_key = None
        self.n = None
    
    # --- Математика (RSA спрощено) ---
    def _gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, e, phi):
        d, x1, x2, y1 = 0, 0, 1, 1
        temp_phi = phi
        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi, e = e, temp2
            x = x2 - temp1 * x1
            y = d - temp1 * y1
            x2, x1 = x1, x
            d, y1 = y1, y
        if temp_phi == 1:
            return d + phi
        return None

    def _calculate_file_hash(self, filepath):
        """Читає файл байтами і рахує його SHA-256 хеш"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(65536) 
                    if not data:
                        break
                    sha256.update(data)
            hex_hash = sha256.hexdigest()
            return int(hex_hash, 16)
        except FileNotFoundError:
            return None

    # --- Основні функції ---
    def generate_keys(self, person_data):
        print(f"\n[1] Генерація ключів на основі даних...")
        # Використовуємо всі дані користувача як "зерно" для випадковості
        seed_val = int(hashlib.sha256(person_data.encode()).hexdigest(), 16)
        random.seed(seed_val)
        
        # Прості числа
        primes = [101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157]
        p = random.choice(primes)
        q = random.choice([x for x in primes if x != p])
        
        self.n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 17 
        while self._gcd(e, phi) != 1:
            e += 2
        d = self._mod_inverse(e, phi)
        
        self.public_key = (e, self.n)
        self.__private_key = (d, self.n)
        print(f" -> Успішно! Ваші унікальні ключі створено.")

    def sign_file(self, filepath):
        if not self.__private_key:
            print("Помилка: Ключі відсутні!")
            return

        print(f"\n[2] Підписання файлу: {filepath}")
        file_hash_int = self._calculate_file_hash(filepath)
        
        if file_hash_int is None:
            print("Помилка: Файл не знайдено.")
            return

        # Адаптація хешу
        hash_to_sign = file_hash_int % self.n
        
        # Шифрування
        d, n = self.__private_key
        signature = pow(hash_to_sign, d, n)
        
        # Збереження підпису
        sig_filename = filepath + ".sig"
        with open(sig_filename, 'w') as f:
            f.write(str(signature))
            
        print(f" -> Підпис збережено у файл: {sig_filename}")
        print(f" -> Значення підпису: {signature}")

    def verify_file(self, filepath):
        sig_filename = filepath + ".sig"
        print(f"\n[3] Перевірка файлу: {filepath}")
        
        if not os.path.exists(filepath) or not os.path.exists(sig_filename):
            print("Помилка: Не знайдено оригінальний файл або файл підпису (.sig)")
            return

        # Читаємо підпис
        with open(sig_filename, 'r') as f:
            try:
                signature = int(f.read().strip())
            except ValueError:
                print("Помилка: Файл підпису пошкоджено.")
                return

        # Рахуємо та розшифровуємо
        current_hash_int = self._calculate_file_hash(filepath)
        current_hash_mod = current_hash_int % self.public_key[1] 

        e, n = self.public_key
        decrypted_hash = pow(signature, e, n)

        print(f" -> Хеш файлу (розрахований): {current_hash_mod}")
        print(f" -> Хеш з підпису (розшифрований): {decrypted_hash}")

        if current_hash_mod == decrypted_hash:
            print(" -> РЕЗУЛЬТАТ: [  Файл цілісний, підпис ДІЙСНИЙ]")
        else:
            print(" -> РЕЗУЛЬТАТ: [  УВАГА! Файл змінено або підпис підроблено!]")

# --- ЗАПУСК ---
if __name__ == "__main__":
    system = FileDigitalSignature()
    
    print("КРОК 1. Налаштування власника")
    
    # ТУТ ТЕПЕР ВВОДИМО ВСІ ДАНІ
    prizvishe = input("Введіть ваше прізвище: ")
    data_nar = input("Введіть дату народження (напр. 15031995): ")
    secret = input("Введіть секретне слово: ")
    
    # Збираємо все в один рядок
    full_info = prizvishe + data_nar + secret
    system.generate_keys(full_info)

    while True:
        print("\n--- МЕНЮ ---")
        print("1. Підписати файл (Створити .sig)")
        print("2. Перевірити файл (Потрібен файл та .sig)")
        print("3. Вихід")
        
        choice = input("Ваш вибір: ")
        
        if choice == '1':
            path = input("Введіть шлях до файлу (наприклад test.txt): ")
            path = path.replace('"', '') 
            system.sign_file(path)
            
        elif choice == '2':
            path = input("Введіть шлях до файлу: ")
            path = path.replace('"', '')
            system.verify_file(path)
            
        elif choice == '3':
            break