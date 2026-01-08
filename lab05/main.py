import base64
import hashlib
from cryptography.fernet import Fernet

class EmailEncryptor:
    def __init__(self, personal_data):
        # Генерація ключа на основі введених даних
        self.key = self._generate_key(personal_data)
        self.cipher = Fernet(self.key)

    def _generate_key(self, data: str) -> bytes:
        """Створює ключ із введеного рядка через SHA-256"""
        hash_object = hashlib.sha256(data.encode())
        return base64.urlsafe_b64encode(hash_object.digest())

    def encrypt_message(self, text: str) -> str:
        """Шифрування тексту"""
        return self.cipher.encrypt(text.encode()).decode()

    def decrypt_message(self, encrypted_text: str) -> str:
        """Розшифрування тексту"""
        return self.cipher.decrypt(encrypted_text.encode()).decode()

def main():
    print("--- Програма для захищеного обміну повідомленнями ---")

    # 1. Введення персональних даних для ключа
    user_info = input("Введіть персональні дані для створення ключа: ")
    
    # 2. Введення Email 
    email = input("Введіть вашу електронну адресу: ")
    
    # 3. Введення повідомлення
    message = input("Введіть текст повідомлення для шифрування: ")

    # Створення об'єкта шифратора
    encryptor = EmailEncryptor(user_info)

    # Процес шифрування
    encrypted_data = encryptor.encrypt_message(message)
    
    print("\n--- РЕЗУЛЬТАТ ШИФРУВАННЯ ---")
    print(f"Відправник: {email}")
    print(f"Зашифровані дані:\n{encrypted_data}")
    print("----------------------------")

    # Процес розшифрування (для демонстрації)
    action = input("\nБажаєте розшифрувати повідомлення? (так/ні): ")
    if action.lower() == "так":
        # Створюємо новий об'єкт з тими ж даними для перевірки
        decrypt_key_info = input("Введіть ключ (персональні дані) для дешифрування: ")
        try:
            temp_decryptor = EmailEncryptor(decrypt_key_info)
            result = temp_decryptor.decrypt_message(encrypted_data)
            print(f"Розшифрований текст: {result}")
        except Exception:
            print("Помилка: Невірний ключ! Доступ до вмісту заборонено.")

if __name__ == "__main__":
    main()