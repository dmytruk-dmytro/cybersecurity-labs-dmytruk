from PIL import Image
import os
import sys

class SteganographyLSB:
    def __init__(self):
        # Маркер кінця повідомлення
        self.delimiter = "#####" 

    def text_to_bits(self, text):
        full_text = text + self.delimiter
        # Перетворюємо рядок у байти (UTF-8)
        text_bytes = full_text.encode('utf-8')
        # Кожен байт перетворюємо у 8 біт
        bits = ''.join(format(byte, '08b') for byte in text_bytes)
        return bits

    def bits_to_text(self, bit_string):
        """Перетворює біти назад у текст"""
        # Розбиваємо на шматки по 8 біт
        byte_values = []
        for i in range(0, len(bit_string), 8):
            chunk = bit_string[i:i+8]
            # Якщо шматок менший 8 біт (кінець файлу), ігноруємо
            if len(chunk) < 8:
                break
            byte_values.append(int(chunk, 2))
        
        # Перетворюємо список чисел назад у байти
        data_bytes = bytes(byte_values)
        
        try:
            # Декодуємо байти в рядок
            full_text = data_bytes.decode('utf-8', errors='ignore')
            
            # Шукаємо маркер кінця
            if self.delimiter in full_text:
                return full_text.split(self.delimiter)[0]
            return full_text
        except:
            return "Не вдалося розшифрувати (сміття)"

    def hide_message(self, image_path, message, output_path):
        """Шифрування"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Файл {image_path} не знайдено!")
            
        img = Image.open(image_path)
        img = img.convert("RGB")
        width, height = img.size
        
        # Отримуємо біти (вже з маркером всередині text_to_bits)
        message_bits = self.text_to_bits(message)
        message_length = len(message_bits)
        max_capacity = width * height * 3

        if message_length > max_capacity:
            raise ValueError(f"Повідомлення завелике! Потрібно біт: {message_length}, є: {max_capacity}")

        pixels = img.load()
        data_index = 0

        print(f"[LOG] Довжина повідомлення: {len(message)} симв. -> {message_length} біт")

        for y in range(height):
            for x in range(width):
                if data_index < message_length:
                    r, g, b = pixels[x, y]
                    
                    if data_index < message_length:
                        r = (r & ~1) | int(message_bits[data_index])
                        data_index += 1
                    if data_index < message_length:
                        g = (g & ~1) | int(message_bits[data_index])
                        data_index += 1
                    if data_index < message_length:
                        b = (b & ~1) | int(message_bits[data_index])
                        data_index += 1

                    pixels[x, y] = (r, g, b)
                else:
                    break
            if data_index >= message_length:
                break
        
        img.save(output_path, "PNG")
        print(f"[SUCCESS] Збережено у: {output_path}")

    def extract_message(self, image_path):
        """Дешифрування"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Файл {image_path} не знайдено!")

        img = Image.open(image_path)
        img = img.convert("RGB")
        pixels = img.load()
        width, height = img.size

        extracted_bits = ""
        # Зчитуємо достатню кількість бітів
        
        count = 0
        max_bits_to_read = width * height * 3 
        
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                extracted_bits += str(r & 1)
                extracted_bits += str(g & 1)
                extracted_bits += str(b & 1)
                
                if len(extracted_bits) > 1000000: # Запобіжник на 1 млн біт
                     break
            if len(extracted_bits) > 1000000:
                break

        return self.bits_to_text(extracted_bits)

# --- ГОЛОВНИЙ БЛОК ---
if __name__ == "__main__":
    stego = SteganographyLSB()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    original_image = os.path.join(script_dir, "input.jpg")
    result_image = os.path.join(script_dir, "output_stego.png")

    try:
           
        # 1. ЗАПИТ НА ВВЕДЕННЯ ТЕКСТУ
        my_data = input(">> Введіть секретне повідомлення: ")

        if not my_data:
            print("[ПОМИЛКА] Ви не ввели жодного тексту!")
        else:
            # 2. Шифруємо
            print("\n--- Етап 1: Шифрування ---")
            stego.hide_message(original_image, my_data, result_image)
            
            # 3. Дешифруємо (перевірка)
            print("\n--- Етап 2: Перевірка (читання з файлу) ---")
            secret_text = stego.extract_message(result_image)
            
            print(f"Витягнутий текст: '{secret_text}'")
            
            if my_data == secret_text:
                print("\n[ОК] Успіх! Повідомлення співпадають.")
            else:
                print("\n[ПОМИЛКА] Тексти відрізняються.")

    except FileNotFoundError:
        print(f"\n[УВАГА] Не знайдено файл input.jpg")
    except Exception as e:
        print(f"\n[КРИТИЧНА ПОМИЛКА] {e}")
        import traceback
        traceback.print_exc()
    
    print("="*40)