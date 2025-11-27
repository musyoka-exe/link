# Link Shortener Application Documentation

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Security Features](#security-features)
4. [Database Schema](#database-schema)
5. [API Endpoints](#api-endpoints)
6. [Admin Panel](#admin-panel)
7. [Installation and Setup](#installation-and-setup)
8. [Environment Variables](#environment-variables)
9. [User Interface](#user-interface)
10. [Additional Pages](#additional-pages)

## Overview

The Link Shortener is a Flask-based web application that allows users to shorten long URLs into compact, shareable links. The application includes an admin panel for monitoring and managing all shortened URLs, along with analytics tracking and security features.

## Features

### Core Functionality
- **URL Shortening**: Converts long URLs into short, unique codes (default 6 characters)
- **QR Code Generation**: Automatically generates QR codes for each shortened URL
- **Click Tracking**: Records and displays the number of clicks for each URL
- **Duplicate Prevention**: Reuses existing short codes for identical URLs
- **Automatic Protocol Handling**: Automatically adds HTTPS protocol to URLs

### Advanced Features
- **Rate Limiting**: Prevents abuse with per-user rate limiting
- **Analytics**: Tracks IP addresses, user agents, and referrers
- **URL Unshortening**: Allows users to see the destination of a shortened URL before clicking
- **Abuse Reporting**: Enables users to report potentially harmful URLs
- **Health Check**: Provides a health check endpoint for monitoring

## Security Features

### Rate Limiting
- Per-user rate limiting using Flask-Limiter
- Limits: 200 requests per day, 50 per hour globally; 10 per minute for URL shortening; 100 per minute for redirects

### Input Sanitization
- URL validation using regex patterns
- Input sanitization to prevent injection attacks
- Length limits on all inputs to prevent buffer overflows

### Authentication & Authorization
- Admin authentication with Flask-Login
- Password hashing using Werkzeug security functions
- Session protection with CSRF tokens
- Secure session handling

### Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (for HTTPS connections)

## Database Schema

The application uses MongoDB with the following collections:

### URLs Collection
```javascript
{
  "_id": ObjectId,
  "original_url": "https://example.com/long/path",
  "short_code": "aBc123",
  "created_at": ISODate,
  "click_count": Number,
  "qr_code_path": "static/qr_codes/aBc123.png"
}
```

### Analytics Collection
```javascript
{
  "_id": ObjectId,
  "short_code": "aBc123",
  "timestamp": ISODate,
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "referrer": "https://referrer.com"
}
```

### Admins Collection
```javascript
{
  "_id": ObjectId,
  "username": "admin",
  "password": "hashed_password",
  "created_at": ISODate,
  "must_change_password": Boolean
}
```

### Reports Collection (for abuse reports)
```javascript
{
  "_id": ObjectId,
  "short_code": "aBc123",
  "short_url": "https://yoursite.com/aBc123",
  "original_url": "https://example.com",
  "reason": "spam|phishing|malware",
  "description": "Description of why the URL is reported",
  "reporter_email": "reporter@example.com",
  "status": "pending|resolved|dismissed",
  "reported_at": ISODate,
  "resolved_at": ISODate,
  "admin_notes": "Notes from admin"
}
```

## API Endpoints

### Public Endpoints
| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| GET | `/` | Main page for URL shortening | None |
| POST | `/shorten` | Shorten a URL | 10/min |
| GET | `/<short_code>` | Redirect to original URL | 100/min |
| GET | `/qr/<short_code>` | Serve QR code image | None |
| GET | `/health` | Health check endpoint | None |
| GET | `/unshorten` | Page to unshorten URLs | 20/min |
| POST | `/unshorten` | Submit URL to unshorten | 20/min |
| GET | `/report` | Page to report abuse | 5/min |
| POST | `/report` | Submit abuse report | 5/min |
| GET | `/terms` | Terms of service page | None |
| GET | `/privacy` | Privacy policy page | None |

### Admin Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/admin/login` | Admin login page |
| GET | `/admin/logout` | Admin logout |
| GET/POST | `/admin/change-password` | Change admin password |
| GET | `/admin/dashboard` | Admin dashboard |
| GET | `/admin/urls` | View all URLs |
| GET | `/admin/analytics` | View analytics |
| POST | `/admin/delete/<short_code>` | Delete a URL |
| GET | `/admin/reports` | View abuse reports |
| POST | `/admin/report/<report_id>/update` | Update report status |

## Admin Panel

### Default Credentials
- **Username**: admin
- **Password**: Auto-generated (see console log on first run)

### Features
- **Dashboard**: Shows total URLs, total clicks, and top URLs by click count
- **URL Management**: View, search, and delete all shortened URLs
- **Analytics**: View detailed analytics including IP addresses, user agents, and timestamps
- **Reports**: Manage abuse reports with status tracking (pending/resolved/dismissed)
- **Security**: Forced password change on first login

### Security Measures
- Default admin password is required to be changed on first login
- Session protection with Flask-Login
- Access restricted to authenticated users only

## Installation and Setup

### Prerequisites
- Python 3.7+
- MongoDB (local or cloud instance)

### Installation Steps
1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up environment variables (see Environment Variables section)
4. Run the application:
   ```bash
   python app.py
   ```

### Running in Production
For production deployment, it's recommended to use a WSGI server like Gunicorn:
```bash
gunicorn app:app -b 0.0.0.0:5000
```

## Environment Variables

The application requires the following environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| SECRET_KEY | Flask secret key for session security | `your-super-secret-key-here-keep-it-safe` |
| MONGODB_URI | MongoDB connection string | `mongodb://localhost:27017/` |
| DEFAULT_ADMIN_PASSWORD | (Optional) Default admin password | `secure_password` |

## User Interface

### Main Page (`/`)
- Clean, simple interface for URL shortening
- Input field for long URL
- Submit button to generate short URL
- Display of generated short URL and QR code
- Responsive design for mobile and desktop

### Shortened URL Display
- Shows the original and shortened URLs
- QR code image for easy mobile scanning
- Copy-to-clipboard functionality

## Additional Pages

### Terms of Service (`/terms`)
Legal terms and conditions for using the service

### Privacy Policy (`/privacy`)
Privacy policy information (template page)

### Unshorten (`/unshorten`)
Allows users to see where a shortened URL leads before clicking
- Input field for shortened URL
- Displays original URL, creation date, and click count
- Safe browsing verification

### Report Abuse (`/report`)
Mechanism for users to report potentially harmful URLs
- Fields for URL, reason, description, and email
- Reason options: spam, phishing, malware, etc.

### Error Pages
- 404.html: Page not found
- 500.html: Server error

## Technical Implementation Details

### URL Generation
- Uses random alphanumeric characters (a-z, A-Z, 0-9)
- Default length is 6 characters (over 56 billion possible combinations)
- Collision detection with retry mechanism (up to 10 attempts)

### QR Code Generation
- Uses the qrcode library with PIL for image creation
- Standard QR code format with error correction
- Saved to static/qr_codes/ directory
- Automatically deleted when URL is removed

### Analytics Collection
- Non-blocking analytics logging
- Tracks IP address, user agent, and referrer for each click
- No personally identifiable information stored by default

### Error Handling
- Comprehensive error handling throughout the application
- Proper HTTP status codes returned
- Logging of errors for debugging

## Deployment Considerations

### Security
- Never run in debug mode in production
- Use strong, unique secret keys
- Monitor access logs regularly
- Implement additional security measures as needed

### Scaling
- MongoDB collections properly indexed
- Rate limiting to prevent abuse
- Efficient queries for analytics and dashboard views

### Monitoring
- Health check endpoint for uptime monitoring
- Comprehensive logging for debugging
- Analytics for usage monitoring