import os
import sqlite3
import json
from pathlib import Path
from typing import Optional, List, Set, Dict
from datetime import datetime

from flask import Flask, g, redirect, render_template, request, session, url_for, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

APP_DIR = Path(__file__).parent.resolve()
DB_PATH = APP_DIR / "app.db"

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-me")

ALLOWED_EXT = {"png","jpg","jpeg","gif","webp"}

def validate_full_name(full_name: str) -> bool:
    """Валидация ФИО - только буквы, пробелы и дефисы"""
    if not full_name or len(full_name) < 2 or len(full_name) > 100:
        return False
    
    # Проверяем, что содержит только буквы, пробелы и дефисы
    import re
    pattern = r'^[а-яёА-ЯЁa-zA-Z\s\-]+$'
    if not re.match(pattern, full_name):
        return False
    
    # Проверяем, что есть хотя бы одно слово
    words = full_name.split()
    if len(words) < 2:
        return False
    
    # Проверяем, что каждое слово начинается с заглавной буквы
    for word in words:
        if not word[0].isupper():
            return False
    
    return True

def validate_class_name(class_name: str) -> bool:
    """Валидация класса в формате XX-XX"""
    if not class_name:
        return False
    
    import re
    # Паттерн для классов типа 11-01, 10-09, 9-03 и т.д.
    pattern = r'^[1-9]?\d-[0-9]\d$'
    if not re.match(pattern, class_name):
        return False
    
    # Дополнительная проверка: первая цифра должна быть от 1 до 11
    parts = class_name.split('-')
    if len(parts) != 2:
        return False
    
    try:
        grade = int(parts[0])
        if grade < 1 or grade > 11:
            return False
    except ValueError:
        return False
    
    return True

def validate_login(login: str) -> bool:
    """Валидация логина"""
    if not login or len(login) < 3 or len(login) > 20:
        return False
    
    import re
    # Только буквы, цифры, подчеркивания, дефисы и точки
    pattern = r'^[a-zA-Z0-9_\-\.]+$'
    return bool(re.match(pattern, login))

def validate_password(password: str) -> bool:
    """Валидация пароля"""
    return len(password) >= 6

def create_app() -> Flask:
    app = Flask(__name__, template_folder=str(APP_DIR / "templates"), static_folder=str(APP_DIR / "static"))
    app.config.update(SECRET_KEY=FLASK_SECRET_KEY, MAX_CONTENT_LENGTH=10 * 1024 * 1024)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g.db = conn
        return g.db

    @app.teardown_appcontext
    def close_db(exc: Optional[BaseException]) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def column_exists(db: sqlite3.Connection, table: str, column: str) -> bool:
        rows = db.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r["name"] == column for r in rows)

    def init_db() -> None:
        db = get_db()
        
        # Users table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                class_name TEXT NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )
        
        # Add last_login column if it doesn't exist
        if not column_exists(db, "users", "last_login"):
            db.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
        
        # Tasks table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                answer TEXT NOT NULL,
                case_sensitive INTEGER NOT NULL DEFAULT 0,
                image_path TEXT,
                answer_format TEXT DEFAULT 'multiple',
                task_type TEXT DEFAULT 'multiple_choice'
            )
            """
        )
        
        # Add task_type column if it doesn't exist
        if not column_exists(db, "tasks", "task_type"):
            db.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT DEFAULT 'multiple_choice'")
        
        # Options table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                is_correct INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
            """
        )
        
        # User answers table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS user_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                is_correct INTEGER NOT NULL,
                answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
            """
        )
        
        # Chat messages table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                edited_at TIMESTAMP,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        
        # Add new columns if they don't exist
        if not column_exists(db, "chat_messages", "edited_at"):
            db.execute("ALTER TABLE chat_messages ADD COLUMN edited_at TIMESTAMP")
        if not column_exists(db, "chat_messages", "is_deleted"):
            db.execute("ALTER TABLE chat_messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        
        # Theory articles table
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS theory_articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                image_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        
        db.commit()
        
        # Ensure admin chat user exists
        existing_admin = db.execute("SELECT id FROM users WHERE login = ?", ("__admin__",)).fetchone()
        if not existing_admin:
            db.execute(
                "INSERT INTO users (login, password_hash, full_name, class_name, is_blocked) VALUES (?, ?, ?, ?, 0)",
                ("__admin__", "", "Администратор", "Админ"),
            )
            db.commit()

    (APP_DIR / "templates").mkdir(exist_ok=True)
    (APP_DIR / "static").mkdir(exist_ok=True)
    (APP_DIR / "static" / "uploads").mkdir(parents=True, exist_ok=True)

    @app.before_request
    def before_request() -> None:
        init_db()

    def is_admin_logged_in() -> bool:
        return bool(session.get("is_admin", False))

    def is_user_logged_in() -> bool:
        return bool(session.get("user_id"))

    def get_current_user():
        if not is_user_logged_in():
            return None
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    def get_admin_user_id() -> int:
        db = get_db()
        row = db.execute("SELECT id FROM users WHERE login = ?", ("__admin__",)).fetchone()
        if row:
            return int(row["id"]) 
        # Fallback (should not happen because ensured in init_db)
        db.execute(
            "INSERT INTO users (login, password_hash, full_name, class_name, is_blocked) VALUES (?, ?, ?, ?, 0)",
            ("__admin__", "", "Администратор", "Админ"),
        )
        db.commit()
        row = db.execute("SELECT id FROM users WHERE login = ?", ("__admin__",)).fetchone()
        return int(row["id"]) if row else 0

    def _save_image(file_storage):
        if not file_storage or file_storage.filename == "":
            return None
        fname = secure_filename(file_storage.filename)
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext not in ALLOWED_EXT:
            return None
        dest = APP_DIR / "static" / "uploads" / fname
        i = 1
        base = fname[: -(len(ext) + 1)] if ext else fname
        while dest.exists():
            fname_try = f"{base}_{i}.{ext}" if ext else f"{base}_{i}"
            dest = APP_DIR / "static" / "uploads" / fname_try
            i += 1
        file_storage.save(dest)
        return f"uploads/{dest.name}"

    # --- Public routes ---
    @app.get("/")
    def index():
        db = get_db()
        tasks = db.execute("SELECT id, title FROM tasks ORDER BY id DESC").fetchall()
        articles = db.execute("SELECT id, title FROM theory_articles ORDER BY id DESC LIMIT 5").fetchall()
        return render_template("index.html", tasks=tasks, articles=articles, site_name="MedPredProf")

    # --- Favicon route for broad browser support ---
    @app.route("/favicon.ico")
    def favicon():
        # Serve the PNG as favicon; most browsers accept PNG
        return send_from_directory(
            directory=str(APP_DIR / "static"),
            path="uploads/сеч.png",
            mimetype="image/png",
        )

    @app.get("/register")
    def register_form():
        return render_template("register.html", site_name="MedPredProf")

    @app.post("/register")
    def register_post():
        login = request.form.get("login", "").strip()
        password = request.form.get("password", "").strip()
        full_name = request.form.get("full_name", "").strip()
        class_name = request.form.get("class_name", "").strip()
        
        if not all([login, password, full_name, class_name]):
            return render_template("register.html", error="Заполните все поля", site_name="MedPredProf")
        
        # Валидация ФИО
        if not validate_full_name(full_name):
            return render_template("register.html", error="ФИО должно содержать только буквы, пробелы и дефисы. Пример: Иванов Иван Иванович", site_name="MedPredProf")
        
        # Валидация класса
        if not validate_class_name(class_name):
            return render_template("register.html", error="Класс должен быть в формате XX-XX (например: 11-01, 10-09)", site_name="MedPredProf")
        
        # Валидация логина
        if not validate_login(login):
            return render_template("register.html", error="Логин должен содержать только буквы, цифры и символы _-. Длина от 3 до 20 символов", site_name="MedPredProf")
        
        # Валидация пароля
        if not validate_password(password):
            return render_template("register.html", error="Пароль должен содержать минимум 6 символов", site_name="MedPredProf")
        
        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE login = ?", (login,)).fetchone()
        if existing:
            return render_template("register.html", error="Пользователь с таким логином уже существует", site_name="MedPredProf")
        
        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (login, password_hash, full_name, class_name) VALUES (?, ?, ?, ?)",
            (login, password_hash, full_name, class_name)
        )
        db.commit()
        return redirect(url_for("login_form"))

    @app.get("/login")
    def login_form():
        return render_template("login.html", site_name="MedPredProf")

    @app.post("/login")
    def login_post():
        login = request.form.get("login", "").strip()
        password = request.form.get("password", "").strip()
        
        if not login or not password:
            return render_template("login.html", error="Введите логин и пароль", site_name="MedPredProf")
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
        
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Неверный логин или пароль", site_name="MedPredProf")
        
        if user["is_blocked"]:
            return render_template("login.html", error="Ваш аккаунт заблокирован", site_name="MedPredProf")
        
        # Update last login time
        db.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
        db.commit()
        
        session["user_id"] = user["id"]
        return redirect(url_for("index"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/task/<int:task_id>")
    def task_view(task_id: int):
        if not is_user_logged_in():
            return redirect(url_for("login_form"))
        
        db = get_db()
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return redirect(url_for("index"))
        
        if task["task_type"] == "multiple_choice":
            opts = db.execute("SELECT id, text FROM options WHERE task_id = ? ORDER BY id", (task_id,)).fetchall()
            return render_template("task_multiple.html", task=task, options=opts, site_name="MedPredProf")
        else:
            return render_template("task_text.html", task=task, site_name="MedPredProf")

    @app.post("/task/<int:task_id>/submit")
    def task_submit(task_id: int):
        if not is_user_logged_in():
            return redirect(url_for("login_form"))
        
        db = get_db()
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            return redirect(url_for("index"))
        
        user_id = session["user_id"]
        is_correct = False
        
        if task["task_type"] == "multiple_choice":
            selected_ids = set(int(x) for x in request.form.getlist("selected_options[]"))
            correct_ids = set(r["id"] for r in db.execute(
                "SELECT id FROM options WHERE task_id = ? AND is_correct = 1", (task_id,)
            ).fetchall())
            is_correct = selected_ids == correct_ids
        else:
            user_answer = request.form.get("answer", "").strip()
            case_sensitive = bool(task["case_sensitive"])
            normalized_user = " ".join(user_answer.split()) if case_sensitive else " ".join(user_answer.lower().split())
            normalized_correct = " ".join(task["answer"].split()) if case_sensitive else " ".join(task["answer"].lower().split())
            is_correct = normalized_user == normalized_correct
        
        # Save answer
        db.execute(
            "INSERT INTO user_answers (user_id, task_id, is_correct) VALUES (?, ?, ?)",
            (user_id, task_id, 1 if is_correct else 0)
        )
        db.commit()
        
        return render_template("result.html", task=task, is_correct=is_correct, site_name="MedPredProf")

    @app.get("/theory")
    def theory_list():
        db = get_db()
        articles = db.execute("SELECT * FROM theory_articles ORDER BY id DESC").fetchall()
        return render_template("theory_list.html", articles=articles, site_name="MedPredProf")

    @app.get("/theory/<int:article_id>")
    def theory_view(article_id: int):
        db = get_db()
        article = db.execute("SELECT * FROM theory_articles WHERE id = ?", (article_id,)).fetchone()
        if not article:
            return redirect(url_for("theory_list"))
        return render_template("theory_view.html", article=article, site_name="MedPredProf")

    # --- Chat API ---
    @app.get("/api/chat")
    def get_chat_messages():
        if not (is_user_logged_in() or is_admin_logged_in()):
            return jsonify({"error": "Unauthorized"}), 401
        
        db = get_db()
        messages = db.execute(
            """
            SELECT cm.id, cm.message, cm.created_at, cm.edited_at, cm.is_deleted, u.full_name, u.class_name, u.id as user_id
            FROM chat_messages cm
            JOIN users u ON cm.user_id = u.id
            WHERE cm.is_deleted = 0
            ORDER BY cm.created_at DESC
            LIMIT 50
            """
        ).fetchall()
        
        return jsonify([dict(msg) for msg in messages])

    @app.post("/api/chat")
    def send_chat_message():
        # Allow both regular users and admins to send messages
        if not (is_user_logged_in() or is_admin_logged_in()):
            return jsonify({"error": "Unauthorized"}), 401
        
        message = request.json.get("message", "").strip()
        if not message:
            return jsonify({"error": "Empty message"}), 400
        
        db = get_db()
        # Choose sender id: real user or admin synthetic user
        if is_user_logged_in():
            sender_id = session["user_id"]
        else:
            sender_id = get_admin_user_id()
        db.execute("INSERT INTO chat_messages (user_id, message) VALUES (?, ?)", (sender_id, message))
        db.commit()
        
        return jsonify({"success": True})

    @app.delete("/api/chat/<int:message_id>")
    def delete_chat_message(message_id: int):
        if not (is_user_logged_in() or is_admin_logged_in()):
            return jsonify({"error": "Unauthorized"}), 401
        
        db = get_db()
        
        # Check if user owns the message or is admin
        message = db.execute("SELECT user_id FROM chat_messages WHERE id = ?", (message_id,)).fetchone()
        if not message:
            return jsonify({"error": "Message not found"}), 404
        
        current_user_id = session.get("user_id")
        if not is_admin_logged_in() and message["user_id"] != current_user_id:
            return jsonify({"error": "Unauthorized"}), 401
        
        # Soft delete the message
        db.execute("UPDATE chat_messages SET is_deleted = 1 WHERE id = ?", (message_id,))
        db.commit()
        
        return jsonify({"success": True})
    
    @app.put("/api/chat/<int:message_id>")
    def edit_chat_message(message_id: int):
        if not (is_user_logged_in() or is_admin_logged_in()):
            return jsonify({"error": "Unauthorized"}), 401
        
        data = request.get_json()
        new_message = data.get("message", "").strip()
        
        if not new_message:
            return jsonify({"error": "Empty message"}), 400
        
        db = get_db()
        
        # Check if user owns the message or is admin
        message = db.execute("SELECT user_id FROM chat_messages WHERE id = ? AND is_deleted = 0", (message_id,)).fetchone()
        if not message:
            return jsonify({"error": "Message not found"}), 404
        
        current_user_id = session.get("user_id")
        if not is_admin_logged_in() and message["user_id"] != current_user_id:
            return jsonify({"error": "Unauthorized"}), 401
        
        # Update the message
        db.execute(
            "UPDATE chat_messages SET message = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?", 
            (new_message, message_id)
        )
        db.commit()
        
        return jsonify({"success": True})

    # --- Admin routes ---
    @app.get("/admin/login")
    def admin_login_form():
        if is_admin_logged_in():
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", site_name="MedPredProf")

    @app.post("/admin/login")
    def admin_login_post():
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["is_admin"] = True
            # Store admin chat user id for convenience (optional)
            try:
                session["admin_user_id"] = get_admin_user_id()
            except Exception:
                session["admin_user_id"] = None
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Неверный пароль", site_name="MedPredProf")

    @app.get("/admin/logout")
    def admin_logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/admin")
    def admin_dashboard():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        db = get_db()
        tasks = db.execute("SELECT * FROM tasks ORDER BY id DESC").fetchall()
        counts = {r["task_id"]: r["cnt"] for r in db.execute("SELECT task_id, COUNT(*) AS cnt FROM options GROUP BY task_id").fetchall()}
        return render_template("admin_dashboard.html", tasks=tasks, counts=counts, site_name="MedPredProf")

    @app.get("/admin/users")
    def admin_users():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        db = get_db()
        users = db.execute(
            """
            SELECT u.*, 
                   COUNT(ua.id) as tasks_solved,
                   COUNT(CASE WHEN ua.is_correct = 1 THEN 1 END) as correct_answers
            FROM users u
            LEFT JOIN user_answers ua ON u.id = ua.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
            """
        ).fetchall()
        
        return render_template("admin_users.html", users=users, site_name="MedPredProf")

    @app.post("/admin/users/<int:user_id>/toggle_block")
    def admin_toggle_user_block(user_id: int):
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        db = get_db()
        user = db.execute("SELECT is_blocked FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            new_status = 1 - user["is_blocked"]
            db.execute("UPDATE users SET is_blocked = ? WHERE id = ?", (new_status, user_id))
            db.commit()
        
        return redirect(url_for("admin_users"))

    @app.get("/admin/tasks/new")
    def admin_new_task_form():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        return render_template("admin_add_task.html", site_name="MedPredProf")

    @app.post("/admin/tasks")
    def admin_create_task():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        task_type = request.form.get("task_type", "multiple_choice")
        image_path = _save_image(request.files.get("image"))
        
        if not title:
            return render_template("admin_add_task.html", error="Укажите название", site_name="MedPredProf")

        db = get_db()
        
        if task_type == "multiple_choice":
            cur = db.execute(
                "INSERT INTO tasks (title, description, answer, case_sensitive, image_path, answer_format, task_type) VALUES (?, ?, ?, ?, ?, 'multiple', 'multiple_choice')",
                (title, description, "", 0, image_path),
            )
            task_id = cur.lastrowid

            texts = request.form.getlist("option_text[]")
            checked_idx = set(int(x) for x in request.form.getlist("option_correct_idx[]") if x.isdigit())
            for idx, txt in enumerate(texts):
                txt = (txt or "").strip()
                if not txt:
                    continue
                is_corr = 1 if idx in checked_idx else 0
                db.execute("INSERT INTO options (task_id, text, is_correct) VALUES (?, ?, ?)", (task_id, txt, is_corr))
        else:
            answer = request.form.get("answer", "").strip()
            case_sensitive = 1 if request.form.get("case_sensitive") == "on" else 0
            db.execute(
                "INSERT INTO tasks (title, description, answer, case_sensitive, image_path, answer_format, task_type) VALUES (?, ?, ?, ?, ?, 'text', 'text_input')",
                (title, description, answer, case_sensitive, image_path),
            )
        
        db.commit()
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/tasks/<int:task_id>/delete")
    def admin_delete_task(task_id: int):
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        db = get_db()
        db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        db.commit()
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin/theory/new")
    def admin_new_theory_form():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        return render_template("admin_add_theory.html", site_name="MedPredProf")

    @app.post("/admin/theory")
    def admin_create_theory():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        image_path = _save_image(request.files.get("image"))
        
        if not title or not content:
            return render_template("admin_add_theory.html", error="Заполните название и содержание", site_name="MedPredProf")

        db = get_db()
        db.execute(
            "INSERT INTO theory_articles (title, content, image_path) VALUES (?, ?, ?)",
            (title, content, image_path)
        )
        db.commit()
        return redirect(url_for("theory_list"))

    @app.post("/admin/theory/<int:article_id>/delete")
    def admin_delete_theory(article_id: int):
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        db = get_db()
        # Получаем информацию о статье для удаления связанного файла
        article = db.execute("SELECT image_path FROM theory_articles WHERE id = ?", (article_id,)).fetchone()
        
        if article:
            # Удаляем файл изображения, если он существует
            if article["image_path"]:
                image_file = APP_DIR / "static" / article["image_path"]
                if image_file.exists():
                    try:
                        image_file.unlink()
                    except OSError:
                        pass  # Игнорируем ошибки удаления файла
            
            # Удаляем статью из базы данных
            db.execute("DELETE FROM theory_articles WHERE id = ?", (article_id,))
            db.commit()
        
        return redirect(url_for("admin_theory_management"))

    @app.get("/admin/theory")
    def admin_theory_management():
        if not is_admin_logged_in():
            return redirect(url_for("admin_login_form"))
        
        db = get_db()
        articles = db.execute("SELECT * FROM theory_articles ORDER BY id DESC").fetchall()
        return render_template("admin_theory_management.html", articles=articles, site_name="MedPredProf")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
