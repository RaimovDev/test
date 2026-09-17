from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "test.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            [
                ("admin", "SuperSecret123", "admin@example.com"),
                ("bek", "password1", "bek@example.com"),
                ("test", "test123", "test@example.com"),
            ],
        )
    conn.commit()
    conn.close()


HOME_PAGE = """
<!doctype html>
<html>
<head><title>O'quv Test Sayti</title></head>
<body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
  <h1>O'quv maqsadidagi test sayt</h1>
  <p>Bu sayt faqat kiberxavfsizlikni amaliy o'rganish uchun yaratilgan. Bu yerda ataylab zaifliklar mavjud.</p>
  <ul>
    <li><a href="/login">Login sahifasi (SQL Injection uchun)</a></li>
    <li><a href="/search?q=salom">Qidiruv (XSS uchun)</a></li>
    <li><a href="/profile?id=1">Profil (IDOR uchun)</a></li>
  </ul>
</body>
</html>
"""

LOGIN_PAGE = """
<!doctype html>
<html>
<head><title>Login</title></head>
<body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
  <h2>Login</h2>
  <form method="POST">
    Username: <input type="text" name="username"><br><br>
    Password: <input type="password" name="password"><br><br>
    <input type="submit" value="Kirish">
  </form>
  <p>{{ message|safe }}</p>
  <p><a href="/">Bosh sahifaga qaytish</a></p>
</body>
</html>
"""


@app.route("/")
def home():
    return HOME_PAGE


# --- ATAYLAB ZAIF: SQL Injection ---
# Bu yerda foydalanuvchi kiritgan qiymat to'g'ridan-to'g'ri SQL so'roviga
# qo'shilyapti (string birlashtirish orqali). Bu noto'g'ri usul --
# to'g'ri usul parametrlashtirilgan so'rov (masalan "WHERE username=?").
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(query)
            user = cur.fetchone()
        except sqlite3.Error as e:
            message = f"SQL xatosi: {e}"
            user = None
        if user:
            message = f"Xush kelibsiz, {user[1]}! (SQL so'rovi: {query})"
        elif not message:
            message = f"Login yoki parol xato. (SQL so'rovi: {query})"
    return render_template_string(LOGIN_PAGE, message=message)


# --- ATAYLAB ZAIF: Reflected XSS ---
# Qidiruv so'zi hech qanday tozalashsiz (escape qilinmasdan) sahifaga
# to'g'ridan-to'g'ri chiqarilyapti.
@app.route("/search")
def search():
    q = request.args.get("q", "")
    page = f"""
    <html><body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
    <h2>Qidiruv natijasi</h2>
    <p>Siz qidirgan so'z: {q}</p>
    <p><a href="/">Bosh sahifaga qaytish</a></p>
    </body></html>
    """
    return page


# --- ATAYLAB ZAIF: IDOR (Insecure Direct Object Reference) ---
# Har qanday foydalanuvchi ID raqamini o'zgartirib, boshqa
# foydalanuvchining ma'lumotini ko'rishi mumkin -- ruxsat tekshiruvi yo'q.
@app.route("/profile")
def profile():
    user_id = request.args.get("id", "1")
    db = get_db()
    cur = db.cursor()
    cur.execute(f"SELECT id, username, email FROM users WHERE id={user_id}")
    user = cur.fetchone()
    if user:
        return f"""
        <html><body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
        <h2>Profil</h2>
        <p>ID: {user[0]}</p>
        <p>Username: {user[1]}</p>
        <p>Email: {user[2]}</p>
        <p><a href="/">Bosh sahifaga qaytish</a></p>
        </body></html>
        """
    return "Foydalanuvchi topilmadi", 404


init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
