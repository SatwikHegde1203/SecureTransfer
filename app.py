import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from encryption import encrypt_file, decrypt_file

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace this with a secure key
app.config['UPLOAD_FOLDER'] = 'uploads'

# Allowed file extensions for uploads
AUDIO_EXTENSIONS = {'mp3', 'aac', 'wav', 'flac', 'ogg', 'm4a'}
VIDEO_EXTENSIONS = {'mp4', 'webm', 'mkv', 'avi', 'mov'}
DOC_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv'}
ALL_EXTENSIONS = AUDIO_EXTENSIONS | VIDEO_EXTENSIONS | DOC_EXTENSIONS

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Ensure the static/decrypted folder exists
if not os.path.exists(os.path.join('static', 'decrypted')):
    os.makedirs(os.path.join('static', 'decrypted'))

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    
    # Create history table with analysis column
    cursor.execute('''CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        action TEXT,
        analysis TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Check if analysis column exists, if not add it (for migration)
    cursor.execute("PRAGMA table_info(history)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'analysis' not in columns:
        cursor.execute("ALTER TABLE history ADD COLUMN analysis TEXT")
    
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def get_user_id(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def log_history(user_id, filename, action, analysis=""):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO history (user_id, filename, action, analysis) VALUES (?, ?, ?, ?)", (user_id, filename, action, analysis))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return redirect(url_for('login'))


# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check password confirmation
        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('register'))

        # Save the user to the database
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose a different one.", "error")
        finally:
            conn.close()

    return render_template('register.html')


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch the user from the database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        # Verify the password
        if result and result[0] == password:
            session['user'] = username
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.", "error")

    return render_template('login.html')


# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html')


# Unified Page Routes
@app.route('/audio')
def audio_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('audio.html')

@app.route('/video')
def video_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('video.html')

@app.route('/doc')
def doc_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('doc.html')


# Encryption Handlers
@app.route('/encrypt/audio', methods=['POST'])
def encrypt_audio():
    return handle_encryption(AUDIO_EXTENSIONS, 'audio_page', 'Audio')

@app.route('/encrypt/video', methods=['POST'])
def encrypt_video():
    return handle_encryption(VIDEO_EXTENSIONS, 'video_page', 'Video')

@app.route('/encrypt/doc', methods=['POST'])
def encrypt_doc():
    return handle_encryption(DOC_EXTENSIONS, 'doc_page', 'Document')

def handle_encryption(allowed_extensions, redirect_route, type_name):
    if 'user' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash("No file selected!", "error")
        return redirect(url_for(redirect_route))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected!", "error")
        return redirect(url_for(redirect_route))

    if file and allowed_file(file.filename, allowed_extensions):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)

        try:
            encrypted_path = encrypt_file(file_path)
            
            # Log to history with analysis
            user_id = get_user_id(session['user'])
            if user_id:
                analysis = f"Encrypted {type_name} file. Size: {file_size} bytes. Algorithm: Fernet (Symmetric)."
                log_history(user_id, filename, 'encrypt', analysis)
            
            flash(f"File '{filename}' encrypted successfully!", "success")
            return send_file(encrypted_path, as_attachment=True)
        except Exception as e:
            flash(f"Error during encryption: {e}", "error")
            return redirect(url_for(redirect_route))
    else:
        flash(f"Invalid file type. Allowed: {', '.join(allowed_extensions)}", "error")
        return redirect(url_for(redirect_route))


# Decryption Handlers
@app.route('/decrypt/audio', methods=['POST'])
def decrypt_audio():
    return handle_decryption('audio_page', 'Audio')

@app.route('/decrypt/video', methods=['POST'])
def decrypt_video():
    return handle_decryption('video_page', 'Video')

@app.route('/decrypt/doc', methods=['POST'])
def decrypt_doc():
    return handle_decryption('doc_page', 'Document')

@app.route('/decrypt', methods=['GET', 'POST']) # Legacy/Generic
def decrypt_page():
    if request.method == 'GET':
        return render_template('decrypt.html') # Keep generic for now if needed, or redirect
    return handle_decryption('decrypt_page', 'File')

def handle_decryption(redirect_route, type_name):
    if 'user' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash("No file selected!", "error")
        return redirect(url_for(redirect_route))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected!", "error")
        return redirect(url_for(redirect_route))

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)

        try:
            download_path = decrypt_file(file_path)
            if download_path:
                download_path = f'decrypted/{os.path.basename(download_path)}'
                
                # Log to history with analysis
                user_id = get_user_id(session['user'])
                if user_id:
                    analysis = f"Decrypted {type_name} file. Size: {file_size} bytes. Integrity Verified."
                    log_history(user_id, filename, 'decrypt', analysis)
                    
                flash(f"File '{filename}' decrypted successfully!", "success")
                # For unified pages, we might want to just send the file directly or show a link.
                # Since we are redirecting back, we can't easily show a link unless we pass it.
                # But the user asked for "Download your original..." in the steps.
                # send_file is easiest for immediate download.
                return send_file(os.path.join('static', download_path), as_attachment=True)
            else:
                flash("Decryption failed.", "error")
        except Exception as e:
            flash(f"Error: {e}", "error")
            
    return redirect(url_for(redirect_route))


# History Page
@app.route('/history')
def history():
    if 'user' not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for('login'))
        
    user_id = get_user_id(session['user'])
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    history_data = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', history=history_data)


# Settings Page
@app.route('/settings')
def settings():
    if 'user' not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for('login'))
        
    user_id = get_user_id(session['user'])
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Get stats
    cursor.execute("SELECT COUNT(*) FROM history WHERE user_id = ? AND action = 'encrypt'", (user_id,))
    total_encrypted = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM history WHERE user_id = ? AND action = 'decrypt'", (user_id,))
    total_decrypted = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('settings.html', username=session['user'], total_encrypted=total_encrypted, total_decrypted=total_decrypted)

# Profile Page (Redirect to Settings)
@app.route('/profile')
def profile():
    return redirect(url_for('settings'))


# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)