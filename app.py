from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import pywhatkit
import schedule
from werkzeug.security import generate_password_hash, check_password_hash  # Ensure this is imported
import threading
import time
import datetime
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress the warning
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)  # Ensure this field exists
    password = db.Column(db.String(200), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_name = db.Column(db.String(100), nullable=False)
    task_description = db.Column(db.String(255), nullable=True)
    task_date = db.Column(db.String(10), nullable=False)
    task_time = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)

# Function to send WhatsApp messages
def send_whatsapp_message(phone_number, task_name, task_description, task_date, task_time):
    try:
        now = datetime.datetime.now()
        hour = now.hour
        minute = now.minute + 1

        if minute >= 60:
            minute -= 60
            hour = (hour + 1) % 24

        message = f"Reminder Task: {task_name}\nDescription: {task_description}\nDate: {task_date}\nTime: {task_time}"
        print(f"Preparing to send message: {message} to {phone_number} at {hour}:{minute}")
        pywhatkit.sendwhatmsg(phone_number, message, hour, minute)
        print(f"Message sent to {phone_number} for task: {task_name}")
    except Exception as e:
        print(f"Error sending message: {e}")

# Function to schedule tasks
def schedule_task(phone_number, task_name, task_description, task_date, task_time):
    def job():
        send_whatsapp_message(phone_number, task_name, task_description, task_date, task_time)
    schedule.every().day.at(task_time).do(job)

# Background Scheduler
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

threading.Thread(target=run_scheduler, daemon=True).start()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Fetch the user from the database
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):  # Verify the password
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        
        return "Invalid credentials"  # Show an error message if login fails
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']  # Capture the email
        password = request.form['password']
        
        # Check if the username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return "Username or email already exists. Please choose a different one."
        
        # Hash the password and save the user to the database
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(name=name, username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        # Flash a success message
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        task_name = request.form['task_name']
        task_description = request.form['task_description']
        task_date = request.form['task_date']
        task_time = request.form['task_time']
        phone_number = request.form['phone_number']

        if not phone_number.startswith('+'):
            return "Phone number must include the country code (e.g., +91XXXXXXXXXX)."

        new_task = Task(
            user_id=session['user_id'],
            task_name=task_name,
            task_description=task_description,
            task_date=task_date,
            task_time=task_time,
            phone_number=phone_number
        )
        db.session.add(new_task)
        db.session.commit()

        # Schedule the task
        schedule_task(phone_number, task_name, task_description, task_date, task_time)

    tasks = Task.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', tasks=tasks, user=user)  # Pass the user object

@app.route('/delete-task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = Task.query.filter_by(id=task_id).first()
    if task and task.user_id == session['user_id']:
        db.session.delete(task)
        db.session.commit()
        return "Task deleted successfully", 200
    return "Task not found or unauthorized", 404

@app.route('/edit-task', methods=['POST'])
def edit_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task_id = request.form['task_id']  # Get the task_id from the form
    task = Task.query.filter_by(id=task_id).first()  # Fetch the task using task_id

    if task and task.user_id == session['user_id']:
        # Update the task fields
        task.task_name = request.form['task_name']
        task.task_description = request.form['task_description']
        task.task_date = request.form['task_date']
        task.task_time = request.form['task_time']
        task.phone_number = request.form['phone_number']
        db.session.commit()  # Save changes to the database
        return redirect(url_for('dashboard'))
    return "Task not found or unauthorized", 404

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.get(session['user_id'])
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(new_password, method='sha256')
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('login'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)