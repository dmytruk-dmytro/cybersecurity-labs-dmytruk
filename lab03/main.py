import os
from PIL import Image


class StegoLab:
    def __init__(self):
        self.stop_marker = "<STOP>"  # Маркер кінця повідомлення

    # Допоміжні функції
    def _text_to_bin(self, text):
        """Перетворює текст (UTF-8) у бітовий рядок."""
        # encode('utf-8') дозволяє коректно працювати з УКР мовою
        bits = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
        return bits

    def _bin_to_text(self, bits):
        """Перетворює біти назад у текст."""
        # Розбиваємо по 8 біт
        all_bytes = bytearray()
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) < 8: break
            all_bytes.append(int(byte, 2))

        try:
            return all_bytes.decode('utf-8', errors='ignore')
        except:
            return str(all_bytes)

    # Шифрування
    def _vigenere(self, text, key, decrypt=False):
        """Простий шифр Віженера для додаткового захисту всередині картинки."""
        if not key: return text
        key = key.lower()
        processed = []
        key_idx = 0
        alphabet = "abcdefghijklmnopqrstuvwxyzабвгґдеєжзиіїйклмнопрстуфхцчшщьюя0123456789 ,.!?-_"

        for char in text:
            lower_char = char.lower()
            if lower_char in alphabet:
                idx = alphabet.find(lower_char)
                k_idx = alphabet.find(key[key_idx % len(key)])

                if decrypt:
                    new_idx = (idx - k_idx) % len(alphabet)
                else:
                    new_idx = (idx + k_idx) % len(alphabet)

                new_char = alphabet[new_idx]
                # Зберігаємо оригінальний регістр
                processed.append(new_char.upper() if char.isupper() else new_char)
                key_idx += 1
            else:
                processed.append(char)
        return "".join(processed)

    # Основна логіка
    def hide_message(self):
        print("\n--- РЕЖИМ ПРИХОВУВАННЯ ---")
        img_path = input(" * Введіть шлях до зображення (напр. input.jpg): ").strip()
        if not img_path: img_path = "input.jpg"

        if not os.path.exists(img_path):
            print(f"[!] Помилка: Файл {img_path} не знайдено.")
            return

        message = input(" * Введіть секретне повідомлення: ").strip()
        key = input(" * Введіть секретний ключ (пароль): ").strip()

        try:
            image = Image.open(img_path).convert("RGB")
            width, height = image.size
            pixels = image.load()

            # Шифруємо текст ключем
            encrypted_msg = self._vigenere(message, key)
            # Додаємо маркер
            full_msg = encrypted_msg + self.stop_marker
            # Переводимо в біти
            binary_msg = self._text_to_bin(full_msg)

            total_pixels = width * height
            req_pixels = len(binary_msg)

            print(f"[i] Приховування {len(binary_msg)} біт у {total_pixels} пікселів...")

            if req_pixels > total_pixels * 3:
                print("[!] Помилка: Повідомлення занадто довге для цього зображення!")
                return

            data_idx = 0
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]

                    # Змінюємо R, G, B канали послідовно
                    if data_idx < len(binary_msg):
                        r = (r & ~1) | int(binary_msg[data_idx])
                        data_idx += 1
                    if data_idx < len(binary_msg):
                        g = (g & ~1) | int(binary_msg[data_idx])
                        data_idx += 1
                    if data_idx < len(binary_msg):
                        b = (b & ~1) | int(binary_msg[data_idx])
                        data_idx += 1

                    pixels[x, y] = (r, g, b)
                    if data_idx >= len(binary_msg): break
                if data_idx >= len(binary_msg): break

            output_path = "encoded_image.png"  # Тільки PNG!
            image.save(output_path)
            print(f"[Успіх] Повідомлення приховано та збережено у: {output_path}")

        except Exception as e:
            print(f"[!] Сталася помилка: {e}")

    def extract_message(self):
        print("\n--- РЕЖИМ ВИТЯГУВАННЯ ---")
        img_path = input(" * Введіть шлях до стегоконтейнера (напр. encoded_image.png): ").strip()
        if not img_path: img_path = "encoded_image.png"

        if not os.path.exists(img_path):
            print(f"[!] Файл не знайдено.")
            return

        key = input(" * Введіть секретний ключ для розшифрування: ").strip()

        try:
            image = Image.open(img_path).convert("RGB")
            pixels = image.load()
            width, height = image.size

            binary_data = ""
            print("[i] Початок LSB-аналізу... Читання бітів...")

            # Читаємо біти, поки не знайдемо маркер
            found = False
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    binary_data += str(r & 1)
                    binary_data += str(g & 1)
                    binary_data += str(b & 1)

            # Конвертуємо в текст
            raw_text = self._bin_to_text(binary_data)

            if self.stop_marker in raw_text:
                encrypted_msg = raw_text.split(self.stop_marker)[0]
                print(f"[Успіх] Знайдено маркер кінця повідомлення.")

                # Розшифровуємо
                decrypted_msg = self._vigenere(encrypted_msg, key, decrypt=True)

                print("\n--- ЗНАЙДЕНЕ ПОВІДОМЛЕННЯ ---")
                print(decrypted_msg)
            else:
                print("[!] Маркер не знайдено або ключ невірний (сміття у файлі).")

        except Exception as e:
            print(f"[!] Помилка: {e}")

    def run(self):
        while True:
            print("\n" + "=" * 40)
            print(" ЛР3: СТЕГАНОГРАФІЯ МЕТОДОМ LSB")
            print(" (з шифруванням Віженера та EOF-маркером)")
            print("=" * 40)
            print(" 1. Приховати (Encode) повідомлення")
            print(" 2. Витягти (Decode) повідомлення")
            print(" q. Вийти")

            choice = input(" Ваш вибір (1, 2 або q): ").strip().lower()

            if choice == '1':
                self.hide_message()
            elif choice == '2':
                self.extract_message()
            elif choice == 'q':
                print("Завершення роботи.")
                break
            else:
                print("Невірний вибір.")


if __name__ == "__main__":
    app = StegoLab()
    app.run()