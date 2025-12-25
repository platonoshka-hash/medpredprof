## Приложение задач (Flask)

- Админ: добавлять/удалять задачи
- Пользователь: видеть список, открывать задачу, отправлять ответ и получать проверку
- SQLite, без внешних сервисов

Установка
1) python -m venv .venv
2) .venv\Scripts\activate  (Windows)  или  source .venv/bin/activate (macOS/Linux)
3) pip install -r requirements.txt
4) (необязательно) .env:
   ADMIN_PASSWORD=yourStrongPassword
   FLASK_SECRET_KEY=change_me_please
5) python app.py
Откройте http://127.0.0.1:5000
