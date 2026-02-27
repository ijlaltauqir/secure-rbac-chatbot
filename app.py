from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import logging
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Configure logging
logging.basicConfig(filename='logs.txt', level=logging.INFO)

# ---------------- DATABASE SETUP ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (username, hashed, role))
            conn.commit()
        except:
            return "User already exists!"
        conn.close()

        return redirect('/')

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['username'] = user[1]
            session['role'] = user[3]
            return redirect('/chat')
        else:
            return "Invalid credentials"

    return render_template('login.html')

# ---------------- CHAT ----------------
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect('/')

    response = ""

    if request.method == 'POST':
        message = request.form['message']
        role = session['role']

        sensitive_keywords = ["salary", "confidential", "admin", "database"]

        if any(word in message.lower() for word in sensitive_keywords):
            if role != "admin":
                response = "Access Denied: Insufficient Permissions."
            else:
                response = "Sensitive data accessed successfully."
        else:
            response = "Chatbot Response: Hello, how can I help you?"

        hashed_message = hashlib.sha256(message.encode()).hexdigest()
        log_entry = f"{datetime.now()} | {session['username']} ({role}) | {hashed_message}"
        logging.info(log_entry)

    return render_template('chat.html', response=response)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)