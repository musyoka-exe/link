# Link Shortener

A powerful and secure URL shortening service built with Flask and MongoDB. This application allows users to create short, shareable links with analytics tracking, QR code generation, and an admin dashboard for management.

## Features

### Core Features
- **URL Shortening**: Convert long URLs into compact, unique short codes
- **QR Code Generation**: Automatically generate QR codes for each shortened URL
- **Click Tracking**: Monitor how many times each link is accessed
- **Duplicate Prevention**: Reuse existing short codes for identical URLs
- **Mobile Responsive**: Works perfectly on all devices

### Advanced Features
- **Analytics**: Track IP addresses, user agents, and referrers for each click
- **Admin Dashboard**: Monitor and manage all shortened URLs
- **Rate Limiting**: Protect against abuse with configurable rate limits
- **Security**: Multiple layers of security including input sanitization and CSRF protection
- **URL Unshortening**: Preview where a shortened URL leads before visiting
- **Abuse Reporting**: Allow users to report potentially harmful links

## Installation

### Prerequisites
- Python 3.7+
- MongoDB (local or cloud instance)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd link_shortener
   ```

2. **Create and activate a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the project root with the following:
   ```env
   SECRET_KEY=your-super-secret-key-here-keep-it-safe
   MONGODB_URI=mongodb://localhost:27017/
   # Optional: DEFAULT_ADMIN_PASSWORD=your-secure-password
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   Open your browser and go to `http://localhost:5000`

### Production Deployment
For production, it's recommended to use a WSGI server like Gunicorn:
```bash
gunicorn app:app -b 0.0.0.0:5000
```

## Usage

### Creating Short URLs
1. Navigate to the main page (`/`)
2. Enter the long URL you want to shorten in the input field
3. Click "Shorten URL"
4. Your shortened URL will be displayed, along with a QR code
5. Copy and share your new short URL

### Using the API
The application also supports programmatic URL shortening via the `/shorten` endpoint.

## Admin Panel

### Default Credentials
- **Username**: `admin`
- **Password**: Auto-generated on first run (displayed in console log - change immediately!)

> **Important**: The default admin password is randomly generated on first run. Check your console output for the password and change it immediately after first login.

### Admin Features
- **Dashboard**: View total URLs created, total clicks, and most popular links
- **URL Management**: Browse, search, and delete all shortened URLs
- **Analytics**: Detailed click analytics including IP addresses and user agents
- **Report Management**: Review and respond to abuse reports
- **Account Security**: Change password and manage admin account settings

## Security Features

- **Rate Limiting**: Global limits of 200 requests per day, 50 per hour, with specific limits for different endpoints
- **Input Sanitization**: All user inputs are validated and sanitized to prevent injection attacks
- **Authentication**: Secure admin login with password hashing
- **CSRF Protection**: Cross-site request forgery protection on sensitive endpoints
- **Security Headers**: XSS protection, clickjacking prevention, and content type options
- **Validated URLs**: Only allows properly formatted HTTP/HTTPS URLs

## API Endpoints

### Public Endpoints
- `GET /` - Main page for URL shortening
- `POST /shorten` - Shorten a URL (10 requests per minute limit)
- `GET /<short_code>` - Redirect to original URL (100 requests per minute limit)
- `GET /qr/<short_code>` - Serve QR code image
- `GET /health` - Health check endpoint
- `GET /unshorten` - Preview where a shortened URL leads
- `GET /report` - Report an abusive URL
- `GET /terms` - Terms of service
- `GET /privacy` - Privacy policy

### Admin Endpoints
- `GET/POST /admin/login` - Admin login
- `GET /admin/logout` - Admin logout
- `GET/POST /admin/change-password` - Change admin password
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/urls` - View all URLs
- `GET /admin/analytics` - View analytics
- `POST /admin/delete/<short_code>` - Delete a URL
- `GET /admin/reports` - View abuse reports
- `POST /admin/report/<report_id>/update` - Update report status

## Database Collections

The application uses MongoDB with the following collections:
- `urls` - Stores original URLs and their short codes
- `analytics` - Tracks click analytics
- `admins` - Admin user accounts
- `reports` - Abuse reports (created when needed)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions about the application, please open an issue in the repository.

## Acknowledgments

- Flask framework for the web application foundation
- MongoDB for the database solution
- qrcode library for QR code generation
- Pillow for image processing