import re
from typing import List, Dict, Any, Set

# --- Константи ---
MIN_LENGTH = 8
STRONG_LENGTH = 12


def get_personal_tokens(name_uk: str, surname_uk: str, dob: str) -> Set[str]:
    """
    (Фрагмент 1)
    Генерує набір небезпечних токенів з особистих даних.
    Використовує транслітерацію та різні формати дати.
    """
    tokens = set()

    # --- Генерація токенів ПІБ (Ім'я, Прізвище) ---
    tokens.add(name_uk.lower())
    tokens.add(surname_uk.lower())

    # Додаємо прості транслітеровані версії
    name_tr = "dmytro"
    surname_tr = "dmytruk"
    tokens.add(name_tr)
    tokens.add(surname_tr)

    # Поширені скорочення/псевдоніми
    if name_tr == "dmytro":
        tokens.add("dima")

    # --- Генерація токенів дати народження (Дата) ---
    # ДД.ММ.РРРР (наприклад, 19.05.2004)
    try:
        day, month, year = dob.split('.')
        year_short = year[2:]

        # Компоненти дати
        tokens.add(day)
        tokens.add(month)
        tokens.add(year)
        tokens.add(year_short)

        # Комбінації
        tokens.add(f"{day}{month}")
        tokens.add(f"{day}{month}{year}")
        tokens.add(f"{day}{month}{year_short}")
        tokens.add(f"{surname_tr}{year}")
        tokens.add(f"{surname_tr}{year_short}")
        tokens.add(f"{name_tr}{year}")
        tokens.add(f"{name_tr}{year_short}")
        tokens.add(f"{name_tr}{day}{month}")

    except ValueError:
        print(f"Попередження: Не вдалося розпарсити дату '{dob}'.")

    # Фільтрація занадто коротких токенів, які можуть дати хибні спрацювання
    return {token for token in tokens if len(token) >= 2}


def analyze_password(password: str, pii_tokens: Set[str]) -> Dict[str, Any]:
    """
    (Фрагмент 2 і 3)
    Оцінка паролю за 10-бальною шкалою, застосовуючи бонуси та штрафи.
    """
    score = 0
    issues = []
    pii_matches = []
    password_lower = password.lower()

    # --- Бонуси (Довжина та Складність) ---
    length = len(password)

    # Бонус за довжину
    if length >= STRONG_LENGTH:
        score += 6  #
    elif length >= MIN_LENGTH:
        score += 2
    else:
        issues.append(f"Довжина ({length}) менша за мінімальну ({MIN_LENGTH}).")

    # Бонус за класи символів
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

    char_classes = sum([has_upper, has_lower, has_digit, has_symbol])

    if char_classes == 4:
        score += 4
    elif char_classes == 3:
        score += 2
    else:
        issues.append("Використано менше 3-х класів символів (A-z, 0-9, !@#).")

    # --- Штрафи (Послідовності та PII) ---

    # Штраф за прості послідовності
    if re.search(r'(123|234|345|abc|bcd|qwe|wer)', password_lower):
        score -= 2  #
        issues.append("Пароль містить прості послідовності (123, abc, qwe).")

    # (Фрагмент 2) Штраф за наявність PII
    for token in pii_tokens:
        if token in password_lower:
            pii_matches.append(token)
            score -= 5  #

    if pii_matches:
        issues.append(f"!КРИТИЧНА ВРАЗЛИВІСТЬ: Пароль містить особисті дані!")

    # --- Фінальна оцінка та рекомендації ---

    # (Фрагмент 3) Обмеження оцінки (від 1 до 10)
    final_score = max(1, min(10, score))

    # Формування ярлика
    if final_score == 10:
        complexity = "Дуже сильний (10/10)"
    elif final_score >= 8:
        complexity = f"Сильний ({final_score}/10)"
    elif final_score >= 5:
        complexity = f"Середній ({final_score}/10)"
    else:
        complexity = f"Слабкий ({final_score}/10)"

    return {
        "score": final_score,
        "complexity": complexity,
        "pii_matches": list(set(pii_matches)),  # Унікальні збіги
        "issues": issues
    }


def get_recommendations(result: Dict[str, Any], length: int) -> List[str]:
    """
    (Фрагмент 3)
    Конкретні рекомендації для покращення безпеки.
    """
    recs = []

    if result['pii_matches']:
        recs.append("Уникайте використання будь-яких особистих даних (імені, дати, прізвища).")

    if length < STRONG_LENGTH:
        recs.append(f"⬆Збільште довжину пароля до {STRONG_LENGTH}+ символів для максимального бонусу.")

    if "менше 3-х класів" in ' '.join(result['issues']):
        recs.append("⬆Використовуйте всі 4 класи символів: великі літери, малі літери, цифри та спецсимволи (!@#$).")

    if "прості послідовності" in ' '.join(result['issues']):
        recs.append("Уникайте очевидних послідовностей (напр., '123' або 'abc').")

    if not recs:
        recs.append("Ваш пароль виглядає надійним. Чудова робота!")

    return recs


def main():
    """Основний цикл програми."""
    print("--- АНАЛІЗАТОР ПАРОЛІВ НА ОСНОВІ PII ---")
    print("Програма для тестування безпеки паролів на основі реальних даних студента.")

    # Збір персональних даних
    print("\n[КРОК 1: ЗБІР PII ДЛЯ ТЕСТУВАННЯ]")
    name_uk = input("Введіть ім'я (напр., Дмитро): ")
    surname_uk = input("Введіть прізвище (напр., Дмитрук): ")
    dob = input("Введіть дату народження (ДД.ММ.РРРР, напр. 19.05.2004): ")

    # Генерація небезпечних токенів
    pii_tokens = get_personal_tokens(name_uk, surname_uk, dob)
    print(f"-> Створено {len(pii_tokens)} небезпечних токенів (PII) для аналізу.")

    print("\n[КРОК 2: ТЕСТУВАННЯ ПАРОЛІВ]")
    print("(введіть 'exit' або 'q' для виходу)")

    while True:
        password = input("\nВведіть пароль для аналізу: ")

        if password.lower() in ['exit', 'q']:
            break

        if not password:
            print("Пароль не може бути порожнім.")
            continue

        # Оцінка пароля
        result = analyze_password(password, pii_tokens)

        # Виведення результатів
        print(f"\n--- РЕЗУЛЬТАТ АНАЛІЗУ ПАРОЛЯ: '{password}' ---")
        print(f"ОЦІНКА: {result['complexity']}")

        if result['pii_matches']:
            print(f"\nЗнайдені особисті дані (PII):")
            for match in result['pii_matches']:
                print(f"  - {match}")

        if result['issues']:
            print(f"\nВиявлені проблеми та бонуси:")
            for issue in result['issues']:
                print(f"  {issue}")

        # Рекомендації
        recommendations = get_recommendations(result, len(password))
        print("\nРекомендації:")
        for rec in recommendations:
            print(f"  {rec}")
        print("---------------------------------------------")

    print("\nАналіз завершено. Дякуємо за використання!")


if __name__ == "__main__":
    main()