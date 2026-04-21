import os
import secrets
from datetime import timedelta
from urllib.parse import urlparse, urljoin
from functools import wraps

from flask import Flask, render_template, url_for, flash, redirect, request, session, abort
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from models import db, User, Contact
from forms import RegistrationForm, LoginForm, ContactForm

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Security Configurations
# ------------------------
# Secret key from environment variable
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

# Database Configuration from environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security Configurations
app.config['SESSION_COOKIE_SECURE'] = True      # Transmit cookies only over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True    # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # Prevent CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', secrets.token_hex(32))

# File Upload Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Task 1: Implement Security Headers with Talisman
# For local development without HTTPS, set force_https=False
Talisman(app, 
         force_https=False,  # Set to True in production with HTTPS
         content_security_policy={
             'default-src': "'self'",
             'img-src': "'self' data:",
             'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com",
             'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com",
             'font-src': "'self' https://cdn.jsdelivr.net"
         })

# Task 2: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Task 5: Role-Based Access Control (RBAC) Decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Create database tables
with app.app_context():
    db.create_all()
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin_user = User(username='admin', password_hash=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created! Username: admin, Password: admin123")

# Task 3: Secure File Upload Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    # Principle of Least Privilege: only show contacts for the logged-in user
    contacts = Contact.query.filter_by(owner=current_user).all()
    return render_template('dashboard.html', title='Dashboard', contacts=contacts)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            # Generic error to prevent username enumeration differences 
            flash('Registration unsuccessful. Please use a different username.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# Task 2: Apply rate limiting to login route
@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Only 5 attempts per minute per IP
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # Verify password and use generic error messages to prevent enumeration
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
            login_user(user, remember=False)
            next_page = request.args.get('next')
            # Validate next parameter to prevent open redirects
            if next_page and not is_safe_url(next_page):
                return abort(400)
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()  # Securely clear the entire session
    return redirect(url_for('login'))

# Task 3: File Upload Route
@app.route("/upload", methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            from werkzeug.utils import secure_filename
            filename = secure_filename(file.filename)  # Removes path traversal attempts
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash(f'File {filename} uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('File type not allowed. Allowed: png, jpg, jpeg, gif, pdf', 'danger')
    
    return render_template('upload.html', title='Upload File')

@app.route("/contact/new", methods=['GET', 'POST'])
@login_required
def add_contact():
    form = ContactForm()
    if form.validate_on_submit():
        contact = Contact(name=form.name.data, email=form.email.data, 
                         phone=form.phone.data, message=form.message.data, 
                         owner=current_user)
        db.session.add(contact)
        db.session.commit()
        flash('Contact has been created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_contact.html', title='New Contact', form=form)

@app.route("/contact/<int:contact_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    # Defense against IDOR (Insecure Direct Object Reference)
    if contact.owner != current_user:
        abort(403)
    form = ContactForm()
    if form.validate_on_submit():
        contact.name = form.name.data
        contact.email = form.email.data
        contact.phone = form.phone.data
        contact.message = form.message.data
        db.session.commit()
        flash('Your contact has been updated!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.name.data = contact.name
        form.email.data = contact.email
        form.phone.data = contact.phone
        form.message.data = contact.message
    return render_template('edit_contact.html', title='Edit Contact', form=form, contact=contact)

@app.route("/contact/<int:contact_id>/delete", methods=['POST'])
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    if contact.owner != current_user:
        abort(403)
    db.session.delete(contact)
    db.session.commit()
    flash('Your contact has been deleted!', 'success')
    return redirect(url_for('dashboard'))

# Task 5: Admin-only routes
@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', title='Admin - Users', users=users)

@app.route("/admin/delete_user/<int:user_id>", methods=['GET', 'POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Cannot delete the main admin user!', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted!', 'success')
    return redirect(url_for('admin_users'))

# Secure Error Handling
@app.errorhandler(404)
def error_404(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def error_403(error):
    app.logger.warning(f'Unauthorized access attempt: {error}')
    return render_template('403.html'), 403

@app.errorhandler(429)
def error_429(error):
    return render_template('429.html'), 429

@app.errorhandler(500)
def error_500(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Running in debug mode for local testing only. For production, deploy via a WSGI server.
    app.run(debug=True, port=5000)