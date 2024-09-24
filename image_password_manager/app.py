# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from PIL import Image
import hashlib
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generated secret key
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Securely generate and store the salt
salt_file_path = 'salt.key'

if not os.path.exists(salt_file_path):
    salt = os.urandom(16)
    with open(salt_file_path, 'wb') as f:
        f.write(salt)
else:
    with open(salt_file_path, 'rb') as f:
        salt = f.read()

def image_to_password(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    pixel_data = ''.join([('%02x%02x%02x' % pixel[:3]) for pixel in pixels])
    hash_object = hashlib.sha256(pixel_data.encode())
    hex_dig = hash_object.hexdigest()
    password = hex_dig[:16]
    return password

def generate_key(master_password):
    password = master_password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,  # Securely generated salt
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_password(plain_text, key):
    f = Fernet(key)
    return f.encrypt(plain_text.encode())

def decrypt_password(cipher_text, key):
    f = Fernet(key)
    return f.decrypt(cipher_text).decode()

def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  password BLOB NOT NULL)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        # Handle file uploads
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No image file selected')
            return redirect(request.url)
        if 'master_file' not in request.files or request.files['master_file'].filename == '':
            flash('No master password image selected')
            return redirect(request.url)
        file = request.files['file']
        master_file = request.files['master_file']
        name = request.form['name']

        # Save uploaded files
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        master_filename = secure_filename(master_file.filename)
        master_filepath = os.path.join(app.config['UPLOAD_FOLDER'], master_filename)
        master_file.save(master_filepath)

        # Generate password from image
        try:
            password = image_to_password(filepath)
        except Exception as e:
            flash('Error processing image for password: ' + str(e))
            return redirect(request.url)
        # Generate key from master password image
        try:
            master_password = image_to_password(master_filepath)
            key = generate_key(master_password)
        except Exception as e:
            flash('Error processing master password image: ' + str(e))
            return redirect(request.url)
        # Encrypt the password
        try:
            encrypted_password = encrypt_password(password, key)
        except Exception as e:
            flash('Error encrypting password: ' + str(e))
            return redirect(request.url)
        # Store in database
        try:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute("INSERT INTO passwords (name, password) VALUES (?, ?)", (name, encrypted_password))
            conn.commit()
            conn.close()
        except Exception as e:
            flash('Error storing password in database: ' + str(e))
            return redirect(request.url)
        finally:
            # Clean up uploaded files
            os.remove(filepath)
            os.remove(master_filepath)
        flash('Password added successfully!')
        return redirect(url_for('index'))
    return render_template('add_password.html')

@app.route('/view_passwords', methods=['GET', 'POST'])
def view_passwords():
    if request.method == 'POST':
        if 'master_file' not in request.files or request.files['master_file'].filename == '':
            flash('No master password image selected')
            return redirect(request.url)
        master_file = request.files['master_file']
        master_filename = secure_filename(master_file.filename)
        master_filepath = os.path.join(app.config['UPLOAD_FOLDER'], master_filename)
        master_file.save(master_filepath)
        try:
            master_password = image_to_password(master_filepath)
            key = generate_key(master_password)
        except Exception as e:
            flash('Error processing master password image: ' + str(e))
            return redirect(request.url)
        finally:
            os.remove(master_filepath)
        # Retrieve and decrypt passwords
        try:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute("SELECT name, password FROM passwords")
            passwords = []
            for name, enc_password in c.fetchall():
                try:
                    dec_password = decrypt_password(enc_password, key)
                    passwords.append({'name': name, 'password': dec_password})
                except Exception:
                    passwords.append({'name': name, 'password': 'Unable to decrypt with provided master password'})
            conn.close()
        except Exception as e:
            flash('Error retrieving passwords: ' + str(e))
            return redirect(request.url)
        return render_template('view_passwords.html', passwords=passwords)
    return render_template('enter_master_password.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
