import re

class PasswordAnalyzer:
    def __init__(self, password, user_data):
        """
        Ініціалізація аналізатора.
        :param password: Пароль для перевірки
        :param user_data: Словник з даними: {'first_name': '', 'last_name': '', 'birth_date': 'DD.MM.YYYY'}
        """
        self.password = password
        self.user_data = user_data
        self.score = 0
        self.recommendations = []
        self.analysis_report = {}

    def check_personal_data(self):
        """Перевіряє, чи містить пароль особисті дані."""
        pwd_lower = self.password.lower()
        found_issues = []

        # 1. Перевірка імені та прізвища
        if self.user_data['first_name'].lower() in pwd_lower and len(self.user_data['first_name']) > 0:
            found_issues.append(f"Пароль містить ваше ім'я ({self.user_data['first_name']})")
        if self.user_data['last_name'].lower() in pwd_lower and len(self.user_data['last_name']) > 0:
            found_issues.append(f"Пароль містить ваше прізвище ({self.user_data['last_name']})")

        # 2. Перевірка дати народження (гнучка логіка)
        b_date = self.user_data['birth_date'] 
        # Спробуємо розбити дату, якщо вона введена коректно (DD.MM.YYYY)
        if '.' in b_date and len(b_date.split('.')) == 3:
            day, month, year = b_date.split('.')
            
            # Варіанти дати: рік, день+місяць (1905), повна дата
            if year in self.password:
                found_issues.append(f"Пароль містить рік народження ({year})")
            if (day + month) in self.password:
                found_issues.append(f"Пароль містить дату народження ({day}{month})")
            if b_date in self.password or b_date.replace('.', '') in self.password:
                found_issues.append("Пароль містить повну дату народження")
        
        # Штраф за знайдені збіги
        if found_issues:
            self.analysis_report['personal_data_leak'] = True
            self.analysis_report['leaks'] = found_issues
            return -40 # Великий штраф за використання PII
        
        self.analysis_report['personal_data_leak'] = False
        return 0

    def check_complexity(self):
        """Оцінює технічну складність пароля."""
        score_add = 0
        
        # Довжина
        length = len(self.password)
        if length >= 12:
            score_add += 30
        elif length >= 8:
            score_add += 15
        else:
            self.recommendations.append("Пароль занадто короткий (менше 8 символів).")

        # Різноманітність символів
        has_upper = bool(re.search(r'[A-Z]', self.password))
        has_lower = bool(re.search(r'[a-z]', self.password))
        has_digit = bool(re.search(r'\d', self.password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password))

        types_count = sum([has_upper, has_lower, has_digit, has_special])
        score_add += (types_count * 15) # Більше балів за різноманітність

        if not has_upper: self.recommendations.append("Додайте великі літери (A-Z).")
        if not has_lower: self.recommendations.append("Додайте малі літери (a-z).")
        if not has_digit: self.recommendations.append("Додайте цифри (0-9).")
        if not has_special: self.recommendations.append("Додайте спеціальні символи (!@#$).")

        return score_add

    def run_analysis(self):
        """Головний метод запуску аналізу."""
        base_score = 0
        personal_penalty = self.check_personal_data()
        complexity_score = self.check_complexity()
        
        # Формула підрахунку
        total_raw = base_score + complexity_score + personal_penalty
        
        # Нормалізація до 1-10 (приблизно)
        # Максимально можливий бал близько 90-100.
        final_score = round(total_raw / 10)
        
        return max(1, min(10, final_score))

    def print_report(self):
        score = self.run_analysis()
        print("\n" + "█"*50)
        print(f"ЗВІТ АНАЛІЗУ ПАРОЛЯ: '{self.password}'")
        print("█"*50)
        
        print(f"\n>>> ЗАГАЛЬНА ОЦІНКА БЕЗПЕКИ: {score}/10")
        
        if self.analysis_report.get('personal_data_leak'):
            print("\n[!] УВАГА! ВИЯВЛЕНО ПЕРСОНАЛЬНІ ДАНІ:")
            for leak in self.analysis_report['leaks']:
                print(f"  - {leak}")
            print("  -> Використання особистих даних робить пароль дуже вразливим!")
        else:
            print("\n[+] Персональних даних у паролі не знайдено.")

        print("\n>>> РЕКОМЕНДАЦІЇ:")
        if not self.recommendations and not self.analysis_report.get('personal_data_leak'):
            print("  - Чудова робота! Пароль виглядає надійним.")
        else:
            if self.analysis_report.get('personal_data_leak'):
                print("  - Повністю змініть пароль, прибравши імена та дати.")
            for rec in self.recommendations:
                print(f"  - {rec}")
        print("\n" + "="*50 + "\n")


# --- ГОЛОВНИЙ БЛОК ПРОГРАМИ (Введення даних) ---
if __name__ == "__main__":
    print("\n--- ПРОГРАМА АНАЛІЗУ БЕЗПЕКИ ПАРОЛІВ ---")
    print("Будь ласка, введіть дані користувача для налаштування фільтрів безпеки.\n")
    
    # Введення персональних даних
    in_first_name = input("Введіть ваше Ім'я (латиницею): ").strip()
    in_last_name = input("Введіть ваше Прізвище (латиницею): ").strip()
    in_birth_date = input("Введіть Дату народження (формат DD.MM.YYYY): ").strip()

    # Створення профілю
    current_user_profile = {
        'first_name': in_first_name,
        'last_name': in_last_name,
        'birth_date': in_birth_date
    }

    print("\n--- НАЛАШТУВАННЯ ЗАВЕРШЕНО. ПОЧИНАЄМО ТЕСТУВАННЯ ---")
    
    # Цикл для перевірки паролів
    while True:
        in_password = input("Введіть пароль для перевірки (або 'exit' для виходу): ").strip()
        
        if in_password.lower() == 'exit':
            print("Роботу завершено.")
            break
            
        if not in_password:
            print("Ви не ввели пароль!")
            continue

        # Запуск аналізу
        analyzer = PasswordAnalyzer(in_password, current_user_profile)
        analyzer.print_report()