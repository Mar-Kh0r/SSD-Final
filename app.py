from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///students.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'My_Secr3t1$Th15')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('PERMANENT_SESSION_LIFETIME', 3600))

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
limiter.init_app(app)

# Security headers using Flask-Talisman
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", 'https:'],
    'img-src': ["'self'", 'data:', 'https:']
}
Talisman(app, content_security_policy=csp, force_https=True, frame_options='DENY', strict_transport_security=True)
# Talisman(app, content_security_policy=csp, frame_options='DENY', strict_transport_security=True)


# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/security.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# Log a message indicating the app has started
app.logger.info("Application startup")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Models
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll = db.Column(db.String(20), unique=True, nullable=False)
    marks = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(100), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# WTForms
class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField('Signup')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered!')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MarksEntryForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    roll = StringField('Roll No', validators=[DataRequired()])
    marks = StringField('Marks', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

# Routes
@limiter.limit("5 per minute")
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"New user signup: {email}")
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session.permanent = True
            app.logger.info(f"User login successful: {email}")
            flash('Login successful!', 'success')
            return redirect(url_for('mainpage'))
        else:
            app.logger.warning(f"Failed login attempt for email: {email}")
            flash('Invalid credentials, please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    user_name = session.pop('user_name', 'Unknown')
    session.pop('user_id', None)
    app.logger.info(f"User logout: {user_name}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/marks')
@login_required
def marks():
    students = Student.query.all()
    return render_template('marks.html', students=students)

@limiter.limit("5 per minute")
@app.route('/marks-entry', methods=['GET', 'POST'])
@login_required
def marks_entry():
    form = MarksEntryForm()
    students = Student.query.all()
    edit_data = None

    if request.args.get('roll'):
        edit_roll = request.args.get('roll')
        edit_data = Student.query.filter_by(roll=edit_roll).first()
        if edit_data:
            form.name.data = edit_data.name
            form.roll.data = edit_data.roll
            form.marks.data = edit_data.marks
            form.email.data = edit_data.email

    if form.validate_on_submit():
        student_data = {
            'name': form.name.data,
            'roll': form.roll.data,
            'marks': form.marks.data,
            'email': form.email.data
        }

        if request.form['action'] == 'Save' and edit_data:
            edit_data.name = student_data['name']
            edit_data.roll = student_data['roll']
            edit_data.marks = student_data['marks']
            edit_data.email = student_data['email']
            db.session.commit()
            app.logger.info(f"Updated student: {edit_data.roll}")
            flash('Student data updated successfully!', 'success')
            return redirect(url_for('marks_entry'))

        elif request.form['action'] == 'Add':
            if not Student.query.filter_by(roll=student_data['roll']).first():
                new_student = Student(**student_data)
                db.session.add(new_student)
                db.session.commit()
                app.logger.info(f"New student added: {student_data['roll']}")
                flash('Student added successfully!', 'success')
                return redirect(url_for('marks_entry'))
            else:
                app.logger.warning(f"Attempt to add duplicate roll number: {student_data['roll']}")
                flash('Roll number already exists!', 'danger')

    return render_template('index.html', form=form, students=students, edit_data=edit_data)

@app.route('/', methods=['GET'])
def mainpage():
    return render_template('mainpage.html')

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"404 error: {request.url}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 error: {request.url}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, port=8080, host="0.0.0.0", ssl_context=('cert.pem', 'key.pem'))
