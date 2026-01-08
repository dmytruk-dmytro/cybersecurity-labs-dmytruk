import os
import time
from PIL import Image
from cryptography.fernet import Fernet

class SecureHideAnalytics:
    def __init__(self):
        # Визначаємо шлях до папки, де лежить скрипт
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.metrics = {}

    def get_full_path(self, filename):
        """Допоміжна функція для створення повного шляху до файлу"""
        return os.path.join(self.base_dir, filename)

    def encrypt_data(self, input_path):
        """Етап 1: AES-шифрування файлу"""
        start_time = time.time()
        
        with open(input_path, 'rb') as f:
            data = f.read()
            
        encrypted_data = self.cipher.encrypt(data)
        
        enc_path = self.get_full_path("encrypted_data.tmp")
        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)
            
        end_time = time.time()
        self.metrics['enc_time'] = end_time - start_time
        self.metrics['enc_size'] = os.path.getsize(enc_path)
        return encrypted_data

    def hide_in_image(self, data, container_path, output_path):
        """Етап 2: LSB-стеганографія"""
        start_time = time.time()
        
        data += b'###END_OF_DATA###'
        binary_data = ''.join(format(byte, '08b') for byte in data)
        
        img = Image.open(container_path).convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        data_idx = 0
        for y in range(height):
            for x in range(width):
                if data_idx < len(binary_data):
                    r, g, b = pixels[x, y]
                    new_r = (r & ~1) | int(binary_data[data_idx])
                    pixels[x, y] = (new_r, g, b)
                    data_idx += 1
                else:
                    break
            if data_idx >= len(binary_data): break
            
        img.save(output_path, format='PNG')
        
        end_time = time.time()
        self.metrics['stego_time'] = end_time - start_time
        self.metrics['final_size'] = os.path.getsize(output_path)

    def full_recovery(self, stego_path, recovered_path):
        """Повний цикл відновлення оригіналу"""
        img = Image.open(stego_path)
        pixels = img.load()
        width, height = img.size
        
        binary_data = ""
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                binary_data += str(r & 1)
        
        all_bytes = bytearray()
        for i in range(0, len(binary_data), 8):
            byte_val = int(binary_data[i:i+8], 2)
            all_bytes.append(byte_val)
            
        stop_marker = b'###END_OF_DATA###'
        stop_idx = all_bytes.find(stop_marker)
        encrypted_data = bytes(all_bytes[:stop_idx])
        
        decrypted_data = self.cipher.decrypt(encrypted_data)
        with open(recovered_path, 'wb') as f:
            f.write(decrypted_data)

    def print_report(self, original_path, container_path):
        print("\n" + "="*40)
        print(" АНАЛІТИЧНИЙ ЗВІТ SecureHide Analytics")
        print("="*40)
        print(f" * Вхідний файл: {original_path} ({os.path.getsize(original_path)} байт)")
        print(f" * Час шифрування: {self.metrics['enc_time']:.5f} сек")
        print(f" * Розмір після шифрування: {self.metrics['enc_size']} байт")
        print(f" * Файл-контейнер: {container_path} ({os.path.getsize(container_path)} байт)")
        print(f" * Час приховування: {self.metrics['stego_time']:.5f} сек")
        print(f" * Підсумковий розмір: {self.metrics['final_size']} байт")
        print("-" * 40)

if __name__ == "__main__":
    app = SecureHideAnalytics()
    
    # Створюємо шляхи на основі розташування main.py
    input_file = app.get_full_path("secret_source.txt")
    cover_image = app.get_full_path("input_cover.jpg")
    stego_image = app.get_full_path("encoded_output.png")
    output_file = app.get_full_path("restored_data.txt")
    
    # Створення тестового файлу, якщо він відсутній
    if not os.path.exists(input_file):
        with open(input_file, "w", encoding="utf-8") as f: 
            f.write("Секретні дані для Лабораторної роботи 7.")

    if os.path.exists(cover_image):
        print("[i] Виконання процедури захисту...")
        encrypted = app.encrypt_data(input_file)
        app.hide_in_image(encrypted, cover_image, stego_image)
        
        print("[i] Виконання процедури відновлення...")
        app.full_recovery(stego_image, output_file)
        
        app.print_report(input_file, cover_image)
        print(f"[Успіх] Усі файли збережено в папці: {app.base_dir}")
    else:
        print(f"[!] Файл {cover_image} не знайдено. Покладіть зображення в папку зі скриптом.")