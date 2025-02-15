from flask import Flask, render_template, request, redirect, url_for, flash
import bcrypt
import requests
import hashlib
from cryptography.fernet import Fernet
import re
import string
import random
import math

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def generate_master_key():
    key = Fernet.generate_key()
    with open('master.key', 'wb') as key_file:
        key_file.write(key)
    return key

def load_master_key():
    return open('master.key', 'rb').read()

try:
    master_key = load_master_key()
except FileNotFoundError:
    master_key = generate_master_key()

fernet = Fernet(master_key)

def check_password_pwned(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    url = f'https://api.pwnedpasswords.com/range/{first5_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Ошибка API: {res.status_code}')
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return int(count)
    return 0

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def password_strength(password):
    length_score = min(len(password) / 8, 1)
    digit_score = 1 if re.search(r"\d", password) else 0
    upper_score = 1 if re.search(r"[A-Z]", password) else 0
    lower_score = 1 if re.search(r"[a-z]", password) else 0
    symbol_score = 1 if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) else 0
    total_score = (length_score + digit_score + upper_score + lower_score + symbol_score) / 5 * 100
    return total_score

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def encrypt_password(password):
    encrypted = fernet.encrypt(password.encode())
    return encrypted

def decrypt_password(token):
    decrypted = fernet.decrypt(token).decode()
    return decrypted

def estimate_crack_time(password):
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)
    combinations = charset ** len(password)
    crack_time_seconds = combinations / 1e9
    return crack_time_seconds

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']

        breaches = check_password_pwned(password)
        if breaches:
            flash(f'Ваш пароль найден в хакерских утечках {breaches} раз(а)! Рекомендуется сменить пароль.', 'danger')
        else:
            flash('Ваш пароль не найден в известных утечках.', 'success')

        strength = password_strength(password)
        flash(f'Сложность вашего пароля: {strength:.2f}%', 'info')

        crack_time = estimate_crack_time(password)
        if crack_time < 60:
            time_str = f'{crack_time:.2f} секунд'
        elif crack_time < 3600:
            time_str = f'{crack_time/60:.2f} минут'
        elif crack_time < 86400:
            time_str = f'{crack_time/3600:.2f} часов'
        elif crack_time < 31536000:
            time_str = f'{crack_time/86400:.2f} дней'
        else:
            time_str = f'{crack_time/31536000:.2f} лет'
        flash(f'Оценочное время взлома вашего пароля методом перебора: {time_str}', 'warning')

        hashed_password = hash_password(password)
        flash(f'Ваш пароль был безопасно хеширован.', 'info')

        return render_template('index.html', strength=strength)
    return render_template('index.html')

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    if request.method == 'POST':
        length = int(request.form.get('length', 16))
        password = generate_password(length)
        encrypted_password = encrypt_password(password)
        flash('Ваш новый пароль был сгенерирован и зашифрован.', 'success')
        return render_template('generate.html', password=password)
    return render_template('generate.html')

if __name__ == '__main__':
    app.run(debug=True)
