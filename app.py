from flask import Flask, request, jsonify,render_template,redirect,url_for,flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
from flask_login import current_user, LoginManager,login_user,logout_user,login_required
from forms import JournalEntryForm, RegisterForm, LoginForm, User
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
from dotenv import load_dotenv
from textblob import TextBlob
import os
import logging
import base64

load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

client = MongoClient(os.getenv('URI'))
app.db = client.Mental_Journal



# Encryption setup (generate key per user or use a global key for simplicity)
# For production, derive key from user password or store securely

ENCRYPTION_KEY_FILE = 'encryption_key.txt'
def load_or_generate_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            key =  f.read()
            if len(base64.urlsafe_b64decode(key)) == 32:
                    logging.debug(f"Loaded valid Fernet key from {ENCRYPTION_KEY_FILE}")
                    return key
            else:
                logging.warning(f"Invalid key in {ENCRYPTION_KEY_FILE}, generating new key")
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, 'wb') as f:
        f.write(key)
        logging.debug(f"Generated and saved new Fernet key to {ENCRYPTION_KEY_FILE}")
    return key

encryption_key = load_or_generate_key()
cipher = Fernet(encryption_key)



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

logging.basicConfig(level=logging.DEBUG)

@login_manager.user_loader
def load_user(user_id):
    user_data = app.db.Users.find_one({'_id': user_id})
    if user_data:
        logging.debug(f"Loaded user: {user_data['email']} with ID: {user_id}")
        return User(email=user_data['email'], id=str(user_data['_id']))
    return None


@login_required
@app.route('/journal/read', methods=['GET'])
def view_journal(): 
    logging.debug(f"Accessing view_journal for user: {current_user.get_id()}")
    entries = app.db.Journals.find({'user_id': current_user.get_id()})
    decrypted_entries = []
    for entry in entries:
        decrypted_content = cipher.decrypt(entry['content'].encode()).decode()
        decrypted_entries.append({
            'content': decrypted_content,
            'title': entry.get('title', ''),
            'tags': entry.get('tags',[]),
            'sentiment': entry.get('sentiment',{}),
            'timestamp': datetime.fromisoformat(entry.get('timestamp')) if entry.get('timestamp') else None
        })

    return render_template("read.html",entries=decrypted_entries)



@app.route('/journal/write', methods=['GET', 'POST'])
@login_required
def add_entry():
    
    form = JournalEntryForm()
    
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        tags = form.tags.data.split(',') if form.tags.data else []
        
        # Encrypt content
        encrypted_content = cipher.encrypt(content.encode()).decode()

        sentiment = TextBlob(content).sentiment
        sentiment_data = {
            'polarity': sentiment.polarity,  # -1 (negative) to 1 (positive)
            'subjectivity': sentiment.subjectivity  # 0 (objective) to 1 (subjective)
        }

        entry = {
            'user_id': current_user.get_id(),  # Assumes Flask-Login user model
            'title': title,
            'content': encrypted_content,
            'tags': [tag.strip() for tag in tags],
            'sentiment': sentiment_data,
            'timestamp': datetime.now(pytz.timezone('Asia/Kolkata')).isoformat()
        }
        app.db.Journals.insert_one(entry)  
        flash('Journal entry saved successfully!', 'success')
        return redirect(url_for('view_journal'))
    
    return render_template('write.html', form=form)





@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username= form.username.data
        email = form.email.data
        password = form.password.data  # Hash password in production
        
        if app.db.Users.find_one({'username': username}) or app.db.Users.find_one({'email': email}):
            flash('Username or email already exists.', 'danger')
            return render_template('register.html', form=form)
        
        user_id = str(app.db.Users.count_documents({}) + 1)
        user_creds = {
            '_id': user_id,
            'username': username,
            'email': email,
            'password': generate_password_hash(password)
        }
        app.db.Users.insert_one(user_creds)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logging.debug(f"User already authenticated: {current_user.get_id()}")
        return redirect(url_for('view_journal'))
    
    form = LoginForm()
    if form.validate_on_submit():

        username = form.username.data
        password = form.password.data
        logging.debug(f"Login attempt for username: {username}")
        user_data = app.db.Users.find_one({'username': username})
        if user_data:
            if user_data and check_password_hash(user_data['password'], password): 
                # Verify hashed password in production 
                user = User(user_data['email'], str(user_data['_id']))  
                login_user(user,remember=form.remember.data) 
                logging.debug(f"User {username} logged in, session: {session.get('_user_id')}")
                flash('Login successful!', 'success')
                return redirect(url_for('view_journal'))
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                flash('Invalid username or password.', 'danger')
        else:
            logging.warning(f"Login attempt with non-existent username: {username}")
            flash('User does not exists Please Sign UP', 'danger')

    return render_template('login.html', form=form, title='Login')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)