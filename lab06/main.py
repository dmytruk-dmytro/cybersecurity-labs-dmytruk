import sqlite3

def setup_database():
    """Я створюю розширену базу даних із вигаданими співробітниками."""
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE employees (
            id INTEGER, 
            first_name TEXT, 
            last_name TEXT, 
            position TEXT, 
            private_info TEXT
        )
    """)
    
    # Я заповнюю таблицю великим списком вигаданих даних
    employees = [
        (1, "Артем", "Бондаренко", "Керівник відділу", "Пароль до сервера: 624524"),
        (2, "Вікторія", "Шевченко", "Бухгалтер", "Пароль до сервера: 764745"),
        (3, "Дмитро", "Ткаченко", "Програміст", "Пароль до сервера: 348645"),
        (4, "Олена", "Кравченко", "HR-менеджер", "Пароль до сервера: 78934"),
        (5, "Ігор", "Мороз", "Системний адміністратор", "Пароль до сервера: 4564378"),
        (6, "Світлана", "Павленко", "Маркетолог", "Пароль до сервера: 678642"),
        (7, "Максим", "Лисенко", "Дизайнер", "Пароль до сервера: 146786"),
        (8, "Наталія", "Козак", "Юрист", "Пароль до сервера: 945635"),
        (9, "Сергій", "Вовк", "Аналітик", "Пароль до сервера: 789725"),
        (10, "Юлія", "Савченко", "Секретар", "Пароль до сервера: 645387")
    ]
    cursor.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?)", employees)
    connection.commit()
    return connection

def vulnerable_search(connection, search_term):
    """Я реалізував пошук, який вразливий до SQL-ін'єкції."""
    cursor = connection.cursor()
    # Запит шукає збіг або в імені, або в прізвищі
    query = (
        "SELECT first_name, last_name, position, private_info FROM employees "
        "WHERE first_name = '" + search_term + "' OR last_name = '" + search_term + "'"
    )
    print(f"\n[!] SQL-запит (ВРАЗЛИВИЙ): {query}")
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        return f"Сталася помилка: {e}"

def secure_search(connection, search_term):
    """Я реалізував захищений пошук із використанням плейсхолдерів."""
    cursor = connection.cursor()
    # Безпечний спосіб передачі даних
    query = (
        "SELECT first_name, last_name, position, private_info FROM employees "
        "WHERE first_name = ? OR last_name = ?"
    )
    print(f"\n[v] SQL-запит (БЕЗПЕЧНИЙ): {query}")
    cursor.execute(query, (search_term, search_term))
    return cursor.fetchall()

def main():
    """Я запускаю інтерактивний стенд."""
    db = setup_database()
    print("=== КОРПОРАТИВНА СИСТЕМА ПОШУКУ ===")
    print("Доступні імена: Артем, Вікторія, Дмитро, Максим, Наталія та інші.")
    
    while True:
        target = input("\nВведіть ім'я або прізвище для пошуку (або 'вийти'): ")
        if target.lower() in ['вийти', 'exit', 'quit']: break

        print("\n" + "="*50)
        print("РЕЗУЛЬТАТ ТЕСТУВАННЯ ВРАЗЛИВОЇ ВЕРСІЇ:")
        res_v = vulnerable_search(db, target)
        if isinstance(res_v, list) and res_v:
            for r in res_v:
                print(f"[*] Знайдено: {r[0]} {r[1]} ({r[2]}) | Приватна примітка: {r[3]}")
        else: print("[-] Даних не знайдено.")

        print("-" * 50)
        print("РЕЗУЛЬТАТ ТЕСТУВАННЯ БЕЗПЕЧНОЇ ВЕРСІЇ:")
        res_s = secure_search(db, target)
        if res_s:
            for r in res_s:
                print(f"[*] Знайдено: {r[0]} {r[1]} ({r[2]}) | Приватна примітка: {r[3]}")
        else: print("[-] Даних не знайдено (ввід оброблено безпечно).")
        print("="*50)

if __name__ == "__main__":
    main()