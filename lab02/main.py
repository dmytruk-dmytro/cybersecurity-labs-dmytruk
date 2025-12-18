import matplotlib.pyplot as plt
from collections import Counter


class CryptoLab:
    def __init__(self):
        # Український алфавіт (33 літери)
        self.alphabet = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"

    # Генерація персонального ключа
    def generate_keys(self, name, dob):
        digits = [int(d) for d in dob if d.isdigit()]
        if not digits:
            shift = 1
        else:
            shift = sum(digits) % len(self.alphabet)

        vigenere_key = name.lower().strip()
        vigenere_key = "".join([c for c in vigenere_key if c in self.alphabet])
        if not vigenere_key: vigenere_key = "ключ"
        return shift, vigenere_key

    # Шифр Цезяря
    def caesar_cipher(self, text, shift, mode='encrypt'):
        result = ""
        actual_shift = shift if mode == 'encrypt' else -shift
        N = len(self.alphabet)
        for char in text:
            if char.lower() in self.alphabet:
                idx = self.alphabet.find(char.lower())
                new_idx = (idx + actual_shift) % N
                new_char = self.alphabet[new_idx]
                result += new_char.upper() if char.isupper() else new_char
            else:
                result += char
        return result

    # Шифр Віженера
    def vigenere_cipher(self, text, key, mode='encrypt'):
        result = ""
        key_indices = [self.alphabet.find(k) for k in key.lower() if k in self.alphabet]
        if not key_indices: key_indices = [0]
        key_len = len(key_indices)
        key_pos = 0
        N = len(self.alphabet)
        for char in text:
            if char.lower() in self.alphabet:
                shift = key_indices[key_pos % key_len]
                actual_shift = shift if mode == 'encrypt' else -shift
                idx = self.alphabet.find(char.lower())
                new_idx = (idx + actual_shift) % N
                new_char = self.alphabet[new_idx]
                result += new_char.upper() if char.isupper() else new_char
                key_pos += 1
            else:
                result += char
        return result

    # Криптоаналіз Brute Force
    def brute_force_caesar(self, ciphertext):
        print("\n--- 6. ЗАПУСК КРИПТОАНАЛІЗУ (BRUTE FORCE) ---")
        print("Перебір усіх можливих зсувів:")
        for s in range(1, len(self.alphabet)):
            attempt = self.caesar_cipher(ciphertext, s, mode='decrypt')
            # Виводимо перші 60 символів
            print(f"Key {s:02d}: {attempt[:60]}...")

    # Графіки
    def plot_frequencies(self, original, caesar, vigenere):
        def get_freq(text):
            text = text.lower()
            letters_only = [c for c in text if c in self.alphabet]
            total = len(letters_only)
            if total == 0: return {char: 0 for char in self.alphabet}
            counts = Counter(letters_only)
            return {char: (counts.get(char, 0) / total) * 100 for char in self.alphabet}

        freq_orig = get_freq(original)
        freq_caesar = get_freq(caesar)
        freq_vigenere = get_freq(vigenere)
        letters = list(self.alphabet)

        fig, axs = plt.subplots(3, 1, figsize=(12, 10))

        axs[0].bar(letters, [freq_orig[l] for l in letters], color='gray')
        axs[0].set_title('Оригінальний текст (Природний розподіл)')
        axs[0].set_ylabel('%')

        axs[1].bar(letters, [freq_caesar[l] for l in letters], color='red')
        axs[1].set_title('Шифр Цезаря (Зсув піків)')
        axs[1].set_ylabel('%')

        axs[2].bar(letters, [freq_vigenere[l] for l in letters], color='green')
        axs[2].set_title('Шифр Віженера (Вирівнювання частот)')
        axs[2].set_ylabel('%')

        plt.tight_layout()
        plt.show()

    # Висновки
    def print_analysis_table(self, text, v_key):
        text_len = len(text)
        v_key_len = len(v_key)

        print("\n--- 5. ПОРІВНЯЛЬНИЙ АНАЛІЗ ---")
        print(f"{'Критерій':<25} | {'Шифр Цезаря':<30} | {'Шифр Віженера':<30}")
        print("-" * 90)

        print(f"{'Довжина результату':<25} | {str(text_len):<30} | {str(text_len):<30}")
        print(f"{'Читабельність':<25} | {'Структура слів збережена':<30} | {'Повна абракадабра':<30}")
        print(f"{'Простір ключів':<25} | {'32 варіанти (вразливий)':<30} | {f'~33^{v_key_len} (висока стійкість)':<30}")

        print("\nВисновки:")
        print("1. Аналіз показав критичну вразливість шифру Цезаря: через малий простір ключів")
        print("   (N=33) та збереження лінгвістичної структури слів, час повного злому методом")
        print("   Brute Force є миттєвим, що підтверджено в пункті 6.")
        print("-" * 90)
        print("2. Шифр Віженера продемонстрував значно вищий рівень ентропії. Використання ключа")
        print("   на основі персональних даних дозволило ефективно маскувати частоти літер, що")
        print("   робить неможливим відновлення тексту без знання довжини ключа.")


# Головний блок
if __name__ == "__main__":
    lab = CryptoLab()

    print("\n" + "=" * 60)
    print("ЛАБОРАТОРНА РОБОТА 2: ЗАХИСТ ОСОБИСТИХ ПОВІДОМЛЕНЬ")
    print("=" * 60)

    # 1. Введення
    print("\n--- 1. ВВЕДЕННЯ ПЕРСОНАЛЬНИХ ДАНИХ ---")
    in_name = input(" * Введіть ваше прізвище (укр): ").strip()
    if not in_name: in_name = "Дмитрук"

    in_dob = input(" * Введіть дату народження (напр., 19.05.2004): ").strip()
    if not in_dob: in_dob = "19.05.2004"

    in_text = input(" * Введіть текст для шифрування (укр): ").strip()
    if not in_text: in_text = "Безпека та захист даних є ключовими дисциплінами."

    # 2. Ключі
    print("\n--- 2. ГЕНЕРАЦІЯ КЛЮЧІВ ---")
    c_shift, v_key = lab.generate_keys(in_name, in_dob)
    print(f"Ключ Цезаря (mod 33): {c_shift}")
    print(f"Ключ Віженера: '{v_key}'")

    # 3. Шифрування
    print("\n--- 3. ШИФРУВАННЯ ---")
    c_encrypted = lab.caesar_cipher(in_text, c_shift)
    v_encrypted = lab.vigenere_cipher(in_text, v_key)


    # Функція для скорочення довгого тексту при виводі
    def short_print(t):
        return (t[:45] + '...') if len(t) > 45 else t


    print(f"Оригінал: {short_print(in_text)}")
    print(f"Цезар:    {short_print(c_encrypted)}")
    print(f"Віженер:  {short_print(v_encrypted)}")

    # Перевірка
    print("\n--- 4. ДЕШИФРУВАННЯ ---")
    c_decrypted = lab.caesar_cipher(c_encrypted, c_shift, mode='decrypt')
    v_decrypted = lab.vigenere_cipher(v_encrypted, v_key, mode='decrypt')

    if c_decrypted == in_text and v_decrypted == in_text:
        print(">> Перевірка цілісності: ПРОЙДЕНО (Тексти співпадають)")
    else:
        print(">> Перевірка цілісності: ПОМИЛКА")

    # 5. Аналіз
    lab.print_analysis_table(in_text, v_key)

    # 6. Бонуси
    input("\nНатисніть Enter для запуску атаки Brute Force та графіків...")
    lab.brute_force_caesar(c_encrypted)

    print("\n--- 7. ВІЗУАЛІЗАЦІЯ ---")
    lab.plot_frequencies(in_text, c_encrypted, v_encrypted)