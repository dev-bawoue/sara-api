# SARA API - Secure AI Response Assistant

A secure FastAPI application with PostgreSQL database for handling AI queries with authentication, audit logging, and admin controls.

##  Quick Start Guide

### Prerequisites

- Python 3.8+
- PostgreSQL installed and running
- Google Gemini API key

### Step 1: Setup Environment

1. **Clone/Create your project directory:**

   ```bash
   mkdir sara-api
   cd sara-api
   ```

2. **Create virtual environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Step 2: Environment Configuration

1. **Create `.env` file in your project root:**

   ```env
   DATABASE_URL=postgresql://your_username:your_password@localhost/SARADATABASE
   SECRET_KEY=your-super-secret-key-here-make-it-very-long-and-random-at-least-32-characters
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   GOOGLE_API_KEY=your-google-gemini-api-key-here
   ```

2. **Update database credentials:**
   - Replace `your_username` and `your_password` with your PostgreSQL credentials
   - Generate a strong SECRET_KEY (you can use: `openssl rand -hex 32`)
   - Add your Google Gemini API key

### Step 3: Database Setup

1. **Update database credentials in `create_db.py`:**

   ```python
   DB_USER = "your_postgres_username"
   DB_PASSWORD = "your_postgres_password"
   ```

2. **Run database initialization:**
   ```bash
   python create_db.py
   ```

### Step 4: Project Structure

Create the following directory structure:

```
sara-api/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── auth.py
│   ├── crud.py
│   ├── dependencies.py
│   └── routers/
│       ├── __init__.py
│       ├── auth.py
│       ├── queries.py
│       └── admin.py
├── .env
├── requirements.txt
├── create_db.py
└── README.md
```

### Step 5: Run the Application

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### Authentication

- `POST /api/register` - Register new user
- `POST /api/login` - Login user
- `GET /api/me` - Get current user info

### Queries

- `POST /api/submit_query` - Submit query to AI
- `GET /api/history` - Get query history
- `GET /api/quota` - Check daily quota status

### Admin (Requires admin privileges)

- `GET /api/admin/logs` - Get audit logs
- `GET /api/admin/users` - Get all users
- `GET /api/admin/stats` - Get system statistics
- `PUT /api/admin/users/{user_id}/toggle` - Toggle user status

##  Security Features

- **JWT Authentication** - Secure token-based authentication
- **Password Hashing** - Bcrypt password hashing
- **Sensitive Data Detection** - Automatic scanning for credit cards, SSNs, etc.
- **Rate Limiting** - Daily query quotas per user
- **Audit Logging** - Complete audit trail of all actions
- **CORS Protection** - Configurable CORS policies

##  Testing the API

### 1. Access API Documentation

Visit: `http://localhost:8000/docs`

### 2. Register a User

```bash
curl -X POST "http://localhost:8000/api/register" \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "password123"}'
```

### 3. Login

```bash
curl -X POST "http://localhost:8000/api/login" \
     -H "Content-Type: application/json" \
     -d '{"email": "user@example.com", "password": "password123"}'
```

### 4. Submit Query (use token from login)

```bash
curl -X POST "http://localhost:8000/api/submit_query" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_TOKEN_HERE" \
     -d '{"query": "What is artificial intelligence?"}'
```

## 🔧 Configuration Options

### Admin Users

Update `ADMIN_EMAILS` in `app/routers/admin.py`:

```python
ADMIN_EMAILS = ["admin@sara.com", "youremail@domain.com"]
```

### Query Limits

Update `MAX_DAILY_QUERIES` in `app/routers/queries.py`:

```python
MAX_DAILY_QUERIES = 100  # Adjust as needed
```

### Sensitive Data Patterns

Update patterns in `app/crud.py`:

```python
SENSITIVE_PATTERNS = [
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
    # Add more patterns as needed
]
```

##  Troubleshooting

### Common Issues

1. **Database Connection Error**

   - Check PostgreSQL is running
   - Verify DATABASE_URL in .env file
   - Ensure database exists

2. **Google API Error**

   - Verify GOOGLE_API_KEY in .env
   - Check API quota and billing

3. **Module Import Errors**
   - Ensure you're in the correct directory
   - Activate virtual environment
   - Install all requirements

### Debug Mode

Run with debug logging:

```bash
python -m uvicorn app.main:app --reload --log-level debug
```

##  Monitoring

- **Health Check:** `GET /health`
- **System Stats:** `GET /api/admin/stats` (admin only)
- **Audit Logs:** `GET /api/admin/logs` (admin only)

## 🔄 Next Steps

1. **Frontend Integration** - Build React/Vue.js frontend
2. **Docker Deployment** - Containerize the application
3. **Redis Caching** - Add caching for better performance
4. **Email Notifications** - Add email alerts for security events
5. **Advanced Analytics** - Add detailed usage analytics

##  License

This project is licensed under the MIT License.
## pip install -r requirements.txt
## .\venv\Scripts\activate
## o run use python -m uvicorn app.main:app --reload