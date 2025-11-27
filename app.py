from flask import Flask, request, render_template, redirect, url_for, jsonify, send_file
from pymongo import MongoClient
import qrcode
from PIL import Image
import os
import random
import string
import re
from datetime import datetime
import io
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Validate required environment variables
required_vars = ['SECRET_KEY', 'MONGODB_URI']
for var in required_vars:
    if not os.environ.get(var):
        logger.error(f"Missing required environment variable: {var}")
        raise EnvironmentError(f"Missing required environment variable: {var}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# MongoDB connection with error handling
try:
    # Add tlsAllowInvalidCertificates for Render compatibility
    client = MongoClient(
        os.environ.get('MONGODB_URI'),
        serverSelectionTimeoutMS=30000,
        connectTimeoutMS=30000,
        tls=True,
        tlsAllowInvalidCertificates=True
    )
    db = client.link_shortener
    urls_collection = db.urls
    analytics_collection = db.analytics
    admin_collection = db.admins
    
    # Test the connection
    client.admin.command('ping')
    logger.info("Connected to MongoDB successfully!")
    
    # Create indexes for better performance
    urls_collection.create_index("short_code", unique=True)
    urls_collection.create_index("original_url")
    urls_collection.create_index("created_at")
    analytics_collection.create_index("timestamp")
    analytics_collection.create_index("short_code")
    logger.info("Database indexes created successfully!")
    
except Exception as e:
    logger.error(f"Error connecting to MongoDB: {e}")
    raise

# Create QR codes directory if it doesn't exist
qr_codes_dir = os.path.join(app.static_folder, 'qr_codes')
os.makedirs(qr_codes_dir, exist_ok=True)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.session_protection = "strong"


def generate_short_code(length=6):
    """Generate a random short code for URL shortening"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


# Create default admin user if not exists (only for first setup)
def create_default_admin():
    """Create default admin user - change password immediately after first login"""
    default_admin = admin_collection.find_one({"username": "admin"})
    if not default_admin:
        # Use environment variable for default password or generate a random one
        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', generate_short_code(12))
        hashed_password = generate_password_hash(default_password)
        admin_collection.insert_one({
            "username": "admin",
            "password": hashed_password,
            "created_at": datetime.utcnow(),
            "must_change_password": True
        })
        logger.warning(f"Default admin created. Username: admin, Password: {default_password}")
        logger.warning("CHANGE THIS PASSWORD IMMEDIATELY!")

create_default_admin()


# Admin User Model
class AdminUser(UserMixin):
    def __init__(self, id, username, password, must_change_password=False):
        self.id = str(id)
        self.username = username
        self.password = password
        self.must_change_password = must_change_password


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        from bson.objectid import ObjectId
        user_data = admin_collection.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return AdminUser(
                user_data["_id"], 
                user_data["username"], 
                user_data["password"],
                user_data.get("must_change_password", False)
            )
    except Exception as e:
        logger.error(f"Error loading user: {e}")
    return None


def is_valid_url(url):
    """Validate if the provided URL is valid"""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None


def sanitize_input(text, max_length=2048):
    """Sanitize user input to prevent injection attacks"""
    if not text:
        return None
    # Remove any null bytes and limit length
    text = text.replace('\x00', '').strip()[:max_length]
    return text


@app.after_request
def set_security_headers(response):
    """Set security headers on all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {e}")
    return render_template('500.html'), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors"""
    return jsonify(error="Rate limit exceeded. Please try again later."), 429


@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check MongoDB connection
        client.admin.command('ping')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503


@app.route('/')
def index():
    """Main page for URL shortening"""
    return render_template('index.html')


@app.route('/shorten', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt  # If using API, implement API key authentication instead
def shorten_url():
    """Shorten the URL and generate QR code"""
    try:
        original_url = sanitize_input(request.form.get('url'))
        
        if not original_url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Clean up the URL - remove extra spaces and common prefixes
        original_url = original_url.strip()
        
        # Remove common prefixes that users might accidentally add
        prefixes_to_remove = ['www.', 'http://', 'https://']
        url_lower = original_url.lower()
        
        for prefix in prefixes_to_remove:
            if url_lower.startswith(prefix):
                original_url = original_url[len(prefix):]
                break
        
        # Now add https:// protocol
        original_url = 'https://' + original_url
        
        if not is_valid_url(original_url):
            return jsonify({'error': 'Invalid URL provided. Please enter a valid domain (e.g., example.com)'}), 400
        
        # Check if URL already exists in database
        existing_url = urls_collection.find_one({'original_url': original_url})
        if existing_url:
            short_code = existing_url['short_code']
            logger.info(f"URL already exists: {short_code}")
        else:
            # Generate a unique short code
            max_attempts = 10
            for _ in range(max_attempts):
                short_code = generate_short_code()
                existing = urls_collection.find_one({'short_code': short_code})
                if not existing:
                    break
            else:
                logger.error("Failed to generate unique short code")
                return jsonify({'error': 'Failed to generate short code'}), 500
            
            # Insert new URL into database
            urls_collection.insert_one({
                'original_url': original_url,
                'short_code': short_code,
                'created_at': datetime.utcnow(),
                'click_count': 0,
                'qr_code_path': f'static/qr_codes/{short_code}.png'
            })
            logger.info(f"New URL shortened: {short_code}")
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # Use request.host_url for better production compatibility
        short_url_full = f"{request.host_url}{short_code}"
        qr.add_data(short_url_full)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code to file
        qr_path = os.path.join(qr_codes_dir, f'{short_code}.png')
        img.save(qr_path)
        
        return jsonify({
            'short_url': short_url_full,
            'original_url': original_url,
            'short_code': short_code,
            'qr_code_path': url_for('static', filename=f'qr_codes/{short_code}.png')
        })
    
    except Exception as e:
        logger.error(f"Error shortening URL: {e}")
        return jsonify({'error': 'An error occurred while shortening the URL'}), 500


@app.route('/<short_code>')
@limiter.limit("100 per minute")
def redirect_to_url(short_code):
    """Redirect to the original URL when short code is accessed"""
    try:
        # Sanitize short code
        short_code = sanitize_input(short_code, max_length=10)
        
        if not short_code:
            return render_template('404.html'), 404
        
        url_doc = urls_collection.find_one({'short_code': short_code})
        
        if not url_doc:
            logger.warning(f"Short code not found: {short_code}")
            return render_template('404.html'), 404
        
        # Update click count
        urls_collection.update_one(
            {'short_code': short_code},
            {'$inc': {'click_count': 1}}
        )
        
        # Log analytics (non-blocking)
        try:
            analytics_collection.insert_one({
                'short_code': short_code,
                'timestamp': datetime.utcnow(),
                'ip_address': request.headers.get('X-Forwarded-For', request.remote_addr),
                'user_agent': request.headers.get('User-Agent', '')[:500],
                'referrer': request.headers.get('Referer', '')[:500]
            })
        except Exception as e:
            logger.error(f"Error logging analytics: {e}")
        
        return redirect(url_doc['original_url'], code=301)
    
    except Exception as e:
        logger.error(f"Error redirecting: {e}")
        return render_template('500.html'), 500


@app.route('/qr/<short_code>')
def get_qr_code(short_code):
    """Serve the QR code image"""
    try:
        short_code = sanitize_input(short_code, max_length=10)
        
        if not short_code:
            return "Invalid QR code", 400
        
        url_doc = urls_collection.find_one({'short_code': short_code})

        if not url_doc:
            return "QR code not found", 404

        qr_path = os.path.join(qr_codes_dir, f'{short_code}.png')

        if os.path.exists(qr_path):
            return send_file(qr_path, mimetype='image/png')
        else:
            return "QR code file not found", 404
    
    except Exception as e:
        logger.error(f"Error serving QR code: {e}")
        return "Error retrieving QR code", 500


# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@csrf.exempt  # Exempt admin login from CSRF for easier access
def admin_login():
    """Admin login page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'), max_length=100)
        password = request.form.get('password', '')

        if not username or not password:
            return render_template('admin_login.html', error='Username and password required')

        admin = admin_collection.find_one({'username': username})

        if admin and check_password_hash(admin['password'], password):
            user = AdminUser(
                admin["_id"], 
                admin["username"], 
                admin["password"],
                admin.get("must_change_password", False)
            )
            login_user(user, remember=True)
            logger.info(f"Admin logged in: {username}")
            
            if user.must_change_password:
                return redirect(url_for('admin_change_password'))
            
            return redirect(url_for('admin_dashboard'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            return render_template('admin_login.html', error='Invalid credentials')

    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    """Admin logout"""
    logger.info(f"Admin logged out: {current_user.username}")
    logout_user()
    return redirect(url_for('admin_login'))


@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
def admin_change_password():
    """Change admin password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not all([current_password, new_password, confirm_password]):
            return render_template('admin_change_password.html', error='All fields are required')
        
        if new_password != confirm_password:
            return render_template('admin_change_password.html', error='New passwords do not match')
        
        if len(new_password) < 8:
            return render_template('admin_change_password.html', error='Password must be at least 8 characters')
        
        from bson.objectid import ObjectId
        admin = admin_collection.find_one({'_id': ObjectId(current_user.id)})
        
        if not admin or not check_password_hash(admin['password'], current_password):
            return render_template('admin_change_password.html', error='Current password is incorrect')
        
        # Update password
        admin_collection.update_one(
            {'_id': ObjectId(current_user.id)},
            {
                '$set': {
                    'password': generate_password_hash(new_password),
                    'must_change_password': False,
                    'password_changed_at': datetime.utcnow()
                }
            }
        )
        
        logger.info(f"Password changed for user: {current_user.username}")
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_change_password.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard with statistics"""
    try:
        total_urls = urls_collection.count_documents({})
        total_clicks = sum(url.get('click_count', 0) for url in urls_collection.find())
        
        # Today's statistics
        today = datetime.utcnow().date()
        today_start = datetime(today.year, today.month, today.day)
        urls_today = urls_collection.count_documents({'created_at': {'$gte': today_start}})
        
        # Get top URLs by click count
        top_urls = list(urls_collection.find().sort('click_count', -1).limit(10))

        return render_template('admin_dashboard.html',
                               total_urls=total_urls,
                               total_clicks=total_clicks,
                               urls_today=urls_today,
                               top_urls=top_urls)
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        return render_template('500.html'), 500


@app.route('/admin/urls')
@login_required
def admin_urls():
    """View all shortened URLs"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 20
        skip = (page - 1) * per_page

        urls = list(urls_collection.find().sort('created_at', -1).skip(skip).limit(per_page))
        total_count = urls_collection.count_documents({})
        total_pages = (total_count + per_page - 1) // per_page

        return render_template('admin_urls.html',
                               urls=urls,
                               current_page=page,
                               total_pages=total_pages,
                               total_count=total_count)
    except Exception as e:
        logger.error(f"Error loading URLs: {e}")
        return render_template('500.html'), 500


@app.route('/admin/analytics')
@login_required
def admin_analytics():
    """View analytics data"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 100
        skip = (page - 1) * per_page
        
        analytics = list(analytics_collection.find().sort('timestamp', -1).skip(skip).limit(per_page))
        total_count = analytics_collection.count_documents({})
        total_pages = (total_count + per_page - 1) // per_page
        
        return render_template('admin_analytics.html', 
                               analytics=analytics,
                               current_page=page,
                               total_pages=total_pages)
    except Exception as e:
        logger.error(f"Error loading analytics: {e}")
        return render_template('500.html'), 500


@app.route('/admin/delete/<short_code>', methods=['POST'])
@login_required
def delete_url(short_code):
    """Delete a shortened URL"""
    try:
        short_code = sanitize_input(short_code, max_length=10)
        
        result = urls_collection.delete_one({'short_code': short_code})
        if result.deleted_count > 0:
            # Delete associated QR code file
            qr_path = os.path.join(qr_codes_dir, f'{short_code}.png')
            if os.path.exists(qr_path):
                os.remove(qr_path)
            
            # Delete associated analytics
            analytics_collection.delete_many({'short_code': short_code})
            
            logger.info(f"URL deleted: {short_code}")
            return jsonify({'success': True})
        
        return jsonify({'success': False, 'error': 'URL not found'}), 404
    
    except Exception as e:
        logger.error(f"Error deleting URL: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500


@app.context_processor
def inject_now():
    """Inject now() function into all templates"""
    return {'now': datetime.utcnow}


# Public pages routes
@app.route('/terms')
def terms_of_service():
    """Terms of Service page"""
    return render_template('terms.html')


@app.route('/privacy')
def privacy_policy():
    """Privacy Policy page"""
    return render_template('privacy.html')


@app.route('/unshorten', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
@csrf.exempt
def unshorten_url():
    """Unshorten a URL to see the original destination"""
    if request.method == 'POST':
        short_url = sanitize_input(request.form.get('short_url', ''))
        
        if not short_url:
            return render_template('unshorten.html', error='Please provide a shortened URL')
        
        # Extract short code from URL
        short_code = short_url.strip().split('/')[-1]
        
        # Look up in database
        url_doc = urls_collection.find_one({'short_code': short_code})
        
        if url_doc:
            return render_template('unshorten.html', 
                                 short_url=short_url,
                                 original_url=url_doc['original_url'],
                                 created_at=url_doc['created_at'],
                                 click_count=url_doc['click_count'])
        else:
            return render_template('unshorten.html', error='Shortened URL not found')
    
    return render_template('unshorten.html')


@app.route('/report', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def report_abuse():
    """Report abuse of a shortened URL"""
    if request.method == 'POST':
        short_url = sanitize_input(request.form.get('short_url', ''))
        reason = sanitize_input(request.form.get('reason', ''), max_length=50)
        description = sanitize_input(request.form.get('description', ''), max_length=1000)
        reporter_email = sanitize_input(request.form.get('email', ''), max_length=100)
        
        if not short_url or not reason or not description:
            return render_template('report.html', error='All fields are required')
        
        # Extract short code
        short_code = short_url.strip().split('/')[-1]
        
        # Check if URL exists
        url_doc = urls_collection.find_one({'short_code': short_code})
        
        if not url_doc:
            return render_template('report.html', error='Shortened URL not found')
        
        # Create reports collection if it doesn't exist
        reports_collection = db.reports
        
        # Store report
        reports_collection.insert_one({
            'short_code': short_code,
            'short_url': short_url,
            'original_url': url_doc['original_url'],
            'reason': reason,
            'description': description,
            'reporter_email': reporter_email,
            'status': 'pending',
            'reported_at': datetime.utcnow(),
            'resolved_at': None,
            'admin_notes': None
        })
        
        logger.info(f"Abuse report submitted for: {short_code}")
        
        return render_template('report.html', success=True)
    
    return render_template('report.html')


@app.route('/admin/reports')
@login_required
def admin_reports():
    """View abuse reports"""
    try:
        reports_collection = db.reports
        status_filter = request.args.get('status', 'all')
        
        if status_filter == 'all':
            query = {}
        else:
            query = {'status': status_filter}
        
        reports = list(reports_collection.find(query).sort('reported_at', -1))
        
        pending_count = reports_collection.count_documents({'status': 'pending'})
        resolved_count = reports_collection.count_documents({'status': 'resolved'})
        dismissed_count = reports_collection.count_documents({'status': 'dismissed'})
        
        return render_template('admin_reports.html', 
                             reports=reports,
                             current_filter=status_filter,
                             pending_count=pending_count,
                             resolved_count=resolved_count,
                             dismissed_count=dismissed_count)
    except Exception as e:
        logger.error(f"Error loading reports: {e}")
        return render_template('500.html'), 500


@app.route('/admin/report/<report_id>/update', methods=['POST'])
@login_required
def update_report(report_id):
    """Update report status"""
    try:
        from bson.objectid import ObjectId
        reports_collection = db.reports
        
        status = request.form.get('status')
        admin_notes = sanitize_input(request.form.get('admin_notes', ''), max_length=1000)
        
        update_data = {
            'status': status,
            'admin_notes': admin_notes,
            'resolved_by': current_user.username,
            'resolved_at': datetime.utcnow()
        }
        
        reports_collection.update_one(
            {'_id': ObjectId(report_id)},
            {'$set': update_data}
        )
        
        logger.info(f"Report {report_id} updated to {status} by {current_user.username}")
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    # Never run with debug=True in production
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=False
    )
