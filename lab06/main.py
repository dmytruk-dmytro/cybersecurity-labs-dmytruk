import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime


# 1: Менеджер бази даних ---
def init_db():
    """Створює БД в оперативній пам'яті та наповнює її тестовими даними."""
    conn = sqlite3.connect(':memory:')  # БД живе тільки поки запущена програма
    cursor = conn.cursor()

    # Створення таблиці студентів
    cursor.execute('''CREATE TABLE students (
                        id INTEGER PRIMARY KEY,
                        full_name TEXT,
                        faculty TEXT,
                        scholarship INTEGER,
                        secret_data TEXT)''')

    # Створення таблиці користувачів (для адмінки)
    cursor.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT,
                        role TEXT)''')

    # Наповнення даними
    students_data = [
        (1, 'Дмитрук Дмитро', 'Інженерія програмного забезпечення', 2000, 'Паспорт: AB123456'),
        (2, 'Іванов Іван', 'Кібербезпека', 1700, 'Паспорт: XY987654'),
        (3, 'Петров Петро', 'Маркетинг', 1900, 'Паспорт: CC555555'),
        (4, 'Super Admin', 'OFFICE', 99999, 'ROOT_KEY_XYZ')
    ]
    cursor.executemany('INSERT INTO students VALUES (?,?,?,?,?)', students_data)

    users_data = [
        (1, 'admin', 'super_secure_pass', 'Administrator'),
        (2, 'guest', '12345', 'User')
    ]
    cursor.executemany('INSERT INTO users VALUES (?,?,?,?)', users_data)

    conn.commit()
    return conn


# 2: Логіка вразливостей та захисту

def waf_check(input_str):
    """Web Application Firewall: шукає сигнатури атак."""
    bad_words = ["UNION", "OR", "'", "--", "1=1", "DROP", "SELECT", "CHAR", "XP_"]
    for word in bad_words:
        if word in input_str.upper():
            return False, word
    return True, None


def search_vulnerable(conn, user_input):
    """ВРАЗЛИВИЙ ПОШУК: використовує f-string (конкатенацію)."""
    cursor = conn.cursor()
    # Дірка в безпеці:
    query = f"SELECT * FROM students WHERE full_name = '{user_input}'"
    try:
        # execute виконує скрипт, якщо є крапка з комою (для SQLite injection)
        if ';' in user_input:
            cursor.executescript(query)
            return [], query, "INJECTED"

        cursor.execute(query)
        return cursor.fetchall(), query, "UNSAFE"
    except Exception as e:
        return [], query, str(e)


def search_secure(conn, user_input):
    """БЕЗПЕЧНИЙ ПОШУК: використовує параметризацію (?)."""
    cursor = conn.cursor()
    query = "SELECT * FROM students WHERE full_name = ?"
    try:
        cursor.execute(query, (user_input,))
        return cursor.fetchall(), query, "SECURE"
    except Exception as e:
        return [], query, str(e)


def login_vulnerable(conn, username, password):
    """ВРАЗЛИВИЙ ЛОГІН."""
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        return user, query
    except Exception as e:
        return None, query


def login_secure(conn, username, password):
    """БЕЗПЕЧНИЙ ЛОГІН."""
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone(), query


# 3: Графічний інтерфейс
class HackingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ЛР6: Етичний хакінг | Дмитрук Д.А.")
        self.root.geometry("950x650")

        self.conn = init_db()

        # Стилі
        style = ttk.Style()
        style.theme_use('clam')

        # Вкладки
        tab_control = ttk.Notebook(root)
        self.tab_search = ttk.Frame(tab_control)
        self.tab_login = ttk.Frame(tab_control)
        self.tab_logs = ttk.Frame(tab_control)

        tab_control.add(self.tab_search, text='1. Пошук (Витік даних)')
        tab_control.add(self.tab_login, text='2. Логін (Злам входу)')
        tab_control.add(self.tab_logs, text='3. Логи (IDS)')
        tab_control.pack(expand=1, fill="both")

        self.setup_search_tab()
        self.setup_login_tab()
        self.setup_logs_tab()

    def log_event(self, module, mode, details, status):
        """Запис подій у таблицю логів (IDS)."""
        time = datetime.now().strftime("%H:%M:%S")
        tag = "alert" if status in ["ATTACK DETECTED", "BLOCKED BY WAF"] else "normal"
        self.tree_logs.insert("", 0, values=(time, module, mode, details, status), tags=(tag,))

    def add_context_menu(self, widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="Вирізати", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Копіювати", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Вставити", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()
        menu.add_command(label="Виділити все", command=lambda: widget.select_range(0, 'end'))

        def show_menu(event):
            widget.focus()  # Фокус на поле при кліку
            menu.tk_popup(event.x_root, event.y_root)

        widget.bind("<Button-3>", show_menu)

    # Вкладка 1: Пошук
    def setup_search_tab(self):
        frame = ttk.LabelFrame(self.tab_search, text="SQL Injection: Search Box", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text="Введіть ім'я студента:").pack(anchor="w")
        self.entry_search = ttk.Entry(frame, width=50, font=('Consolas', 10))
        self.entry_search.pack(fill="x", pady=5)
        self.entry_search.insert(0, "Дмитрук Дмитро")

        self.add_context_menu(self.entry_search)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="💀 Знайти (Вразливо)", command=self.do_unsafe_search).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🛡️ Знайти (Безпечно + WAF)", command=self.do_secure_search).pack(side="left",
                                                                                                     padx=5)

        # Таблиця результатів
        cols = ("ID", "ПІБ", "Факультет", "Стипендія", "Секретна інформація")
        self.tree_search = ttk.Treeview(frame, columns=cols, show="headings", height=12)
        for col in cols:
            self.tree_search.heading(col, text=col)
            self.tree_search.column(col, width=120)
        self.tree_search.pack(fill="both", expand=True, pady=10)

    def do_unsafe_search(self):
        inp = self.entry_search.get()
        res, query, status = search_vulnerable(self.conn, inp)

        self.update_table(self.tree_search, res)

        # Проста IDS: якщо повернуло забагато записів і в запиті є OR - це атака
        status_msg = "OK"
        if len(res) > 1 and ("OR" in inp.upper() or "UNION" in inp.upper()):
            status_msg = "ATTACK DETECTED"
            messagebox.showwarning("IDS Alert",
                                   f"Увага! Витік даних. Показано {len(res)} записів.\nВразливий запит виконано.")

        self.log_event("SEARCH", "UNSAFE", query, status_msg)

    def do_secure_search(self):
        inp = self.entry_search.get()

        # 1. WAF Check
        is_safe, bad_word = waf_check(inp)
        if not is_safe:
            self.log_event("SEARCH", "WAF", f"Blocked Input: {inp}", "BLOCKED BY WAF")
            messagebox.showerror("WAF Block", f"Запит заблоковано! Виявлено сигнатуру атаки: {bad_word}")
            return

        # 2. Secure Query
        res, query, status = search_secure(self.conn, inp)
        self.update_table(self.tree_search, res)
        self.log_event("SEARCH", "SECURE", query, "OK")

    # Вкладка 2: Логін
    def setup_login_tab(self):
        frame = ttk.Frame(self.tab_login)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        panel = ttk.LabelFrame(frame, text="Панель адміністратора", padding=20)
        panel.pack()

        ttk.Label(panel, text="Логін:").grid(row=0, column=0, sticky="e", pady=5)
        self.entry_user = ttk.Entry(panel, width=25)
        self.entry_user.grid(row=0, column=1, pady=5)
        self.entry_user.insert(0, "admin")

        self.add_context_menu(self.entry_user)

        ttk.Label(panel, text="Пароль:").grid(row=1, column=0, sticky="e", pady=5)
        self.entry_pass = ttk.Entry(panel, show="*", width=25)
        self.entry_pass.grid(row=1, column=1, pady=5)

        self.add_context_menu(self.entry_pass)

        ttk.Button(panel, text="Вхід (Вразливо)", command=self.do_unsafe_login).grid(row=2, column=0, columnspan=2,
                                                                                     pady=10, sticky="ew")
        ttk.Button(panel, text="Вхід (Безпечно)", command=self.do_secure_login).grid(row=3, column=0, columnspan=2,
                                                                                     pady=5, sticky="ew")

        self.lbl_login_status = ttk.Label(panel, text="Очікування...", foreground="gray", font=('Arial', 10, 'bold'))
        self.lbl_login_status.grid(row=4, column=0, columnspan=2, pady=10)

    def do_unsafe_login(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        user, query = login_vulnerable(self.conn, u, p)

        if user:
            self.lbl_login_status.config(text=f"Вхід дозволено: {user[1]}", foreground="green")
            self.log_event("LOGIN", "UNSAFE", query, "SUCCESS (ADMIN ACCESS)")
        else:
            self.lbl_login_status.config(text="Відмовлено в доступі", foreground="red")
            self.log_event("LOGIN", "UNSAFE", query, "FAILED")

    def do_secure_login(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()

        is_safe, bad_word = waf_check(u)
        if not is_safe:
            self.log_event("LOGIN", "WAF", f"User: {u}", "BLOCKED BY WAF")
            self.lbl_login_status.config(text="Заблоковано WAF", foreground="red")
            return

        user, query = login_secure(self.conn, u, p)
        if user:
            self.lbl_login_status.config(text=f"Вхід дозволено: {user[1]}", foreground="green")
            self.log_event("LOGIN", "SECURE", query, "SUCCESS")
        else:
            self.lbl_login_status.config(text="Невірний логін або пароль", foreground="red")
            self.log_event("LOGIN", "SECURE", query, "FAILED")

    # Вкладка 3: Логи
    def setup_logs_tab(self):
        cols = ("Time", "Module", "Mode", "Details", "Status")
        self.tree_logs = ttk.Treeview(self.tab_logs, columns=cols, show="headings")

        self.tree_logs.heading("Time", text="Час")
        self.tree_logs.column("Time", width=80)
        self.tree_logs.heading("Module", text="Модуль")
        self.tree_logs.column("Module", width=80)
        self.tree_logs.heading("Mode", text="Режим")
        self.tree_logs.column("Mode", width=80)
        self.tree_logs.heading("Details", text="Деталі (SQL / Input)")
        self.tree_logs.column("Details", width=450)
        self.tree_logs.heading("Status", text="Статус")
        self.tree_logs.column("Status", width=120)

        # Кольори для небезпечних подій
        self.tree_logs.tag_configure("alert", background="#ffcccc")
        self.tree_logs.tag_configure("normal", background="white")

        self.tree_logs.pack(fill="both", expand=True, padx=10, pady=10)

    def update_table(self, tree, data):
        for i in tree.get_children():
            tree.delete(i)
        for row in data:
            tree.insert("", "end", values=row)


if __name__ == "__main__":
    root = tk.Tk()
    app = HackingApp(root)
    root.mainloop()