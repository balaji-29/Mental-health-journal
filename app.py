from flask import Flask, request, jsonify,render_template,redirect,url_for,flash, session
from pymongo import MongoClient
from cryptography.fernet import Fernet
from flask_login import current_user, LoginManager,login_user,logout_user,login_required
from forms import JournalEntryForm, RegisterForm, LoginForm, User, ForgotPasswordForm, ResetPasswordForm
from datetime import datetime, timedelta, time
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
from dotenv import load_dotenv
from textblob import TextBlob
import os
import logging
import base64
from flask_mail import Mail, Message
import secrets
import calendar
from calendar_design import calendar_design
from bson.objectid import ObjectId
import random
import plotly
import plotly.graph_objs as go
import json



load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'balajiak9598@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'ypuk lshk gbjk xbgx'     # Replace with your app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'balajiak9598@gmail.com'


client = MongoClient(os.getenv('URI'))
app.db = client.Mental_Journal
mail = Mail(app)



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

happy_emojis = {"e1":"😂","e2":"😍","e3":"😎","e4":"😁","e5":"🤭","e6":"🤫","e7":"😚","e8":"😇","e9":"😉"}
sad_emojis = {"e1":"😢","e2":"😭","e3":"😞","e4":"😔","e5":"😟","e6":"😕","e7":"☹️","e8":"🙁","e9":"😣"}
normal_emojis = {"e1":"🙂","e2":"😐","e3":"😑","e4":"😶","e5":"😏","e6":"🤨","e7":"😬","e8":"🤔","e9":"😴"}
mixed_emojis = {"e1":"🤪","e2":"😵‍💫","e3":"😵","e4":"🤯","e5":"🥴","e6":"😳","e7":"🥳","e8":"😜","e9":"😌"}

@login_manager.user_loader
def load_user(user_id):
    user_data = app.db.Users.find_one({'_id': user_id})
    if user_data:
        logging.debug(f"Loaded user: {user_data['email']} with ID: {user_id}")
        return User(email=user_data['email'], id=str(user_data['_id']))
    return None


# Helper function to get month boundaries
def get_month_boundaries(year, month):
    first_day = datetime(year, month, 1)
    last_day = datetime(year, month, calendar.monthrange(year, month)[1])
    return first_day, last_day

def get_week_boundaries(selected_date):
    # Convert string date (YYYY-MM-DD) to datetime
    selected_date = datetime.strptime(selected_date, '%Y-%m-%d')
    # Find the start of the week (Monday)
    start_of_week = selected_date - timedelta(days=selected_date.weekday())
    # End of the week (Sunday)
    end_of_week = start_of_week + timedelta(days=6)
    return start_of_week, end_of_week

def entry_sentiment(polarity):
    if polarity > 0:
        return 'positive'
    elif polarity < 0:
        return 'negative'
    else:
        return 'neutral'


@login_required
@app.route('/')
def all_journals():
    entries = app.db.Journals.find({'user_id': current_user.get_id()})
    decrypted_entries = []

    # Get year and month from query params or default to current
    year = int(request.args.get('year', datetime.now().year))
    month = int(request.args.get('month', datetime.now().month,type=int))
    selected_date = request.args.get('selected_date', None)

    # Validate month and year
    if month < 1 or month > 12:
        month = datetime.now().month
    if year < 1900 or year > 9999:
        year = datetime.now().year

    # Calculate previous and next months
    prev_year, prev_month = (year, month - 1) if month > 1 else (year - 1, 12)
    next_year, next_month = (year, month + 1) if month < 12 else (year + 1, 1)

    # Generate calendar HTML
    cal = calendar_design(year, month)
    # Fetch entries for the current month
    first_day, last_day = get_month_boundaries(year, month)
    
    entries = app.db.Journals.find({
        'user_id': current_user.get_id(),
        'timestamp': {
            '$gte': first_day.isoformat(),
            '$lte': last_day.isoformat()
        }
    }).sort('date', 1)
    
    date_sentiments = {}
    for entry in entries:
    
        entry_date = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d')
        sentiment = entry.get('sentiment', {})
        polarity = sentiment.get('polarity', 0)
        
        date_sentiments[entry_date] = entry_sentiment(polarity) 
    
    print("date_sentiments",date_sentiments)
    
    if selected_date:
        start_of_week, end_of_week = get_week_boundaries(selected_date)
        print("start_of_week",start_of_week)
        print("end_of_week",end_of_week)
        entries = app.db.Journals.find({
            'user_id': current_user.get_id() ,
            'timestamp': {
                '$gte': start_of_week.isoformat(),
                '$lte': datetime.combine(end_of_week, time.max).isoformat()
            }
        }).sort('date', 1)
        #display_title = f"Entries for Week of {start_of_week.strftime('%B %d, %Y')}"
    else:
        entries = app.db.Journals.find({
            'user_id': current_user.get_id() ,
            'timestamp': {
                '$gte': first_day.isoformat(),
                '$lte': last_day.isoformat()
            }
        }).sort('date', 1)
        #display_title = f"{calendar.month_name[month]} Journal Entries"
    print("selected_date",selected_date)
    for entry in entries:
        print("entry",entry)
        timestamp = datetime.fromisoformat(entry.get('timestamp')) if entry.get('timestamp') else None
        #formatted_date = timestamp.strftime('%a, %B, %d')
        day = timestamp.strftime('%a')
        month = timestamp.strftime('%m')
        date = timestamp.strftime('%d')
        

        decrypted_entries.append({
            'id': str(entry.get('_id')),
            'title': entry.get('title', ''),
            'tags': entry.get('tags',[]),
            'day': day,
            'month': month,
            'date': date 
        })
        print("decrypted_entries",decrypted_entries)

    return render_template(
        'calendar.html',
        calendar=cal,
        year=year,
        month=calendar.month_name[int(month)],
        month_num=int(month),
        prev_year=prev_year,
        current_year=datetime.now().year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        entries=decrypted_entries,
        date_sentiments=date_sentiments,
        selected_date=selected_date
    )



@login_required
@app.route('/entry/<entry_id>')
def entry_detail(entry_id): 
    logging.debug(f"Accessing all_journals for user: {current_user.get_id()}")
        
    # add entry_id to fetch single entry
    entries = app.db.Journals.find({'_id': ObjectId(entry_id), 'user_id': current_user.get_id() })
    decrypted_entries = []
    
    
    for entry in entries:
        sentiment = entry.get('sentiment', {})
        polarity = sentiment.get('polarity', 0)
        polarity_value = entry_sentiment(polarity)
        
        decrypted_content = cipher.decrypt(entry.get('content','').encode()).decode()
        timestamp = datetime.fromisoformat(entry.get('timestamp')) if entry.get('timestamp') else None
        day = timestamp.strftime('%A')
        month = timestamp.strftime('%B')
        date = timestamp.strftime('%d')
        year = timestamp.strftime('%Y')
        
        decrypted_entries.append({
            'content': decrypted_content.title(),
            'title': entry.get('title', '').title(),
            'tags': entry.get('tags',[]),
            'sentiment': polarity_value,
            'day': day.upper(),
            'month': month.upper(), 
            'date': date,
            'year': year,
        })
        #print("decrypted_entries",decrypted_entries)
        if polarity_value == 'positive':
            e1,e2,e3,e4,e5,e6,e7,e8,e9 = happy_emojis.values()
        elif polarity_value == 'negative':  
            e1,e2,e3,e4,e5,e6,e7,e8,e9 = sad_emojis.values()
        elif polarity_value == 'neutral':       
            e1,e2,e3,e4,e5,e6,e7,e8,e9 = normal_emojis.values()

        static_path = os.path.join(os.path.dirname(__file__), 'static', 'quotes.json')
        with open(static_path, 'r', encoding='utf-8') as f:
            quotes = json.load(f)

        quote_val = random.randint(0,19)
        print("quote_val",quote_val)
        quote = quotes[polarity_value][quote_val]
        
        
        
    return render_template("read.html",entries=decrypted_entries,e1=e1,e2=e2,e3=e3,e4=e4,e5=e5,e6=e6,e7=e7,e8=e8,e9=e9,quote=quote)



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
        return redirect(url_for('all_journals'))
    
    return render_template('write.html', form=form, title='New Journal Entry', e1="😂", e2="😍",e3="😎",e4="😁",e5="🤭",e6="🤫",e7="😚",e8="😇",e9="😉")

@app.route('/report', methods=['GET'])
def report():
    pass

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
        return redirect(url_for('all_journals'))
    
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
              
                return redirect(url_for('all_journals'))
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

def generate_reset_token(email):
    user = app.db.Users.find_one({'email': email})
    if user:
        token = secrets.token_urlsafe(32)
        expiry = (datetime.now(pytz.timezone('Asia/Kolkata'))+ timedelta(minutes=3)).isoformat()   # Token valid for 1 hour
        app.db.Users.update_one(
            {'email': email},
            {'$set': {'reset_token': token, 'reset_token_expiry': expiry}}
        )
        return token
    else:
        return "Account not found. Create an account."

def verify_reset_token(token):
    user = app.db.Users.find_one({'reset_token': token})
    if user and user.get('reset_token_expiry') and user['reset_token_expiry'] > datetime.now(pytz.timezone('Asia/Kolkata')).isoformat():
        return user
    return None

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        token = generate_reset_token(form.email.data)
        if token:
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[form.email.data])
            msg.body = f'To reset your password, click the following link: {reset_url}\nIf you did not request this, please ignore this email.'
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'danger')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', form=form, title='Forgot Password')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print(token)
    user = verify_reset_token(token)
    print(user)
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        app.db.Users.update_one(
            {'email': user['email']},
            {'$set': {'password': hashed_password, 'reset_token': None, 'reset_token_expiry': None}}
        )
        flash('Your password has been updated! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form, title='Reset Password', token=token)

@app.route('/journal/sentiment_report', methods=['GET'])
@login_required
def sentiment_report():
    logging.debug(f"Generating sentiment report for user: {current_user.get_id()}")
    # Get date range from query params (default: last 30 days)
    end_date = request.args.get('end_date', datetime.now(pytz.timezone('Asia/Kolkata')).isoformat())
    start_date = request.args.get('start_date', (datetime.now(pytz.timezone('Asia/Kolkata')) - timedelta(days=30)).isoformat())
    try:
        start_date = datetime.fromisoformat(start_date)
        end_date = datetime.fromisoformat(end_date)
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('all_journals'))

    entries = app.db.Journals.find({
        'user_id': current_user.get_id(),
        'timestamp': {'$gte': start_date.isoformat(), '$lte': end_date.isoformat()}
    }).sort('timestamp', 1)

    dates = []
    polarities = []
    subjectivities = []
    for entry in entries:
        try:
            timestamp = datetime.fromisoformat(entry.get('timestamp')).strftime('%Y-%m-%d')
            dates.append(timestamp)
            polarities.append(entry.get('sentiment', {}).get('polarity', 0))
            subjectivities.append(entry.get('sentiment', {}).get('subjectivity', 0))
        except Exception as e:
            logging.error(f"Error processing entry for report: {e}")

    # Create Plotly figure
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates,
        y=polarities,
        mode='lines+markers',
        name='Polarity',
        line=dict(color='#4CAF50')
    ))
    fig.add_trace(go.Scatter(
        x=dates,
        y=subjectivities,
        mode='lines+markers',
        name='Subjectivity',
        line=dict(color='#2196F3')
    ))
    fig.update_layout(
        title='Sentiment Analysis Report',
        xaxis_title='Date',
        yaxis_title='Score',
        yaxis=dict(range=[-1, 1]),
        template='plotly_white'
    )

    # Convert to JSON for template
    graph_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return render_template('sentiment_report.html', graph_json=graph_json, start_date=start_date.isoformat(), end_date=end_date.isoformat())

if __name__ == '__main__':
    app.run(debug=True)