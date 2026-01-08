import string

class CipherDemo:
    def __init__(self, surname, birth_date):
        self.surname = surname
        self.birth_date = birth_date
        self.alphabet = string.ascii_letters  
        
        # 1. Генерація ключів
        self.caesar_key = self._calculate_date_sum(birth_date)
        self.vigenere_key = surname
        
    def _calculate_date_sum(self, date_str):
        """Рахує суму цифр дати для зсуву Цезаря"""
        digits = [int(d) for d in date_str if d.isdigit()]
        if not digits: return 1 # Захист від пустих даних
        return sum(digits)

    # --- Алгоритм Цезаря ---
    def caesar(self, text, decrypt=False):
        shift = self.caesar_key if not decrypt else -self.caesar_key
        result = []
        n = len(self.alphabet)
        
        for char in text:
            if char in self.alphabet:
                idx = self.alphabet.index(char)
                new_idx = (idx + shift) % n
                result.append(self.alphabet[new_idx])
            else:
                result.append(char)
        return "".join(result)

    # --- Алгоритм Віженера ---
    def vigenere(self, text, decrypt=False):
        if not self.vigenere_key: return text # Захист від пустого ключа
        
        result = []
        key = self.vigenere_key
        n = len(self.alphabet)
        key_idx = 0
        
        for char in text:
            if char in self.alphabet:
                shift = self.alphabet.index(key[key_idx % len(key)])
                if decrypt:
                    shift = -shift
                
                char_idx = self.alphabet.index(char)
                new_idx = (char_idx + shift) % n
                result.append(self.alphabet[new_idx])
                
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    # --- Функція аналізу ---
    def run_analysis(self, text):
        print(f"\n{'='*20} ЗВІТ ПРО РОБОТУ {'='*20}")
        print(f"Ключ Віженера (Прізвище): {self.surname}")
        print(f"Ключ Цезаря (Дата -> Сума): {self.birth_date} -> {self.caesar_key}")
        print(f"Вхідний текст: {text}\n")

        # Шифрування
        enc_caesar = self.caesar(text)
        enc_vigenere = self.vigenere(text)
        
        # Дешифрування
        dec_caesar = self.caesar(enc_caesar, decrypt=True)
        dec_vigenere = self.vigenere(enc_vigenere, decrypt=True)

        print(f"--- Результати ---")
        print(f"[Цезар]   Зашифровано: {enc_caesar}")
        print(f"[Цезар]   Розшифровано: {dec_caesar}")
        print("-" * 50)
        print(f"[Віженер] Зашифровано: {enc_vigenere}")
        print(f"[Віженер] Розшифровано: {dec_vigenere}\n")

        print(f"--- Порівняльна таблиця ---")
        row_format = "{:<15} | {:<20} | {:<20}"
        print(row_format.format("Алгоритм", "Читабельність", "Тип ключа"))
        print("-" * 60)
        print(row_format.format("Цезар", "Зберігає структуру", f"Число ({self.caesar_key})"))
        print(row_format.format("Віженер", "Низька (хаос)", f"Слово ({self.surname})"))

# --- БЛОК ЗАПУСКУ ---
if __name__ == "__main__":
    print("Програма порівняння алгоритмів шифрування")
    print("-" * 40)
    
    # Введення даних користувачем
    try:
        user_surname = input("Введіть ваше прізвище (латиницею): ").strip()
        user_date = input("Введіть дату народження (напр. 01.01.2004): ").strip()
        user_text = input("Введіть текст для шифрування (латиницею): ").strip()
        
        if not user_surname or not user_text:
            print("\n[Помилка] Дані не можуть бути пустими!")
        else:
            # Створення об'єкта і запуск
            app = CipherDemo(user_surname, user_date)
            app.run_analysis(user_text)
            
    except Exception as e:
        print(f"\nВиникла помилка: {e}")
    
    input("\nНатисніть Enter, щоб вийти...")