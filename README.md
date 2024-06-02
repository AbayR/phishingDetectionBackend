# Phishing URL Detection API

This project is a FastAPI application for detecting phishing URLs. It includes an admin login system, URL feature extraction, database storage, and model retraining functionality.

## Features

1. **Phishing Detection**: Predicts whether a URL is phishing or legitimate.
2. **Admin Login**: Admin can log in to access restricted endpoints.
3. **Database Storage**: Stores URLs and their features in a SQLite database.
4. **Model Retraining**: Retrains the model based on the URLs in the database.

## Installation

### Prerequisites

- Python 3.7+
- FastAPI
- Uvicorn
- SQLAlchemy
- Joblib
- Pandas
- Requests
- BeautifulSoup4
- Tldextract
- DnsPython
- Passlib
- FastAPI-Login

### Installing Dependencies

```bash
pip install fastapi uvicorn sqlalchemy joblib pandas requests beautifulsoup4 tldextract dnspython passlib fastapi-login
```
### Endpoints
Public Endpoints
POST /predict: Predicts if a URL is phishing or legitimate.

Request Body: {"url": "http://example.com"}
Response: {"url": "http://example.com", "prediction": "legitimate"}
GET /add-url: Renders a form to add a suspected phishing URL.

Response: HTML form to submit a URL.
POST /submit-url: Submits a URL to be added to the database.

Form Data: url=http://example.com
Response: HTML page indicating successful submission and model retraining status.
Admin Endpoints
POST /login: Authenticates an admin user.

Request Form Data: username=admin@example.com, password=123456
Response: Authentication token.
GET /view-urls: Displays all URLs stored in the database. (Admin only)

Response: HTML page with a list of URLs and their features.
Retrain Endpoint
POST /retrain: Retrains the model based on the URLs in the database.
Response: JSON message indicating success or failure.

### Admin Credentials
Email: naiza@gmail.com 

Password: 123123


### Usage
Adding a URL
Go to http://127.0.0.1:8000/add-url.
Enter the URL and submit the form.
The URL will be added to the database and the model will start retraining.
Viewing URLs (Admin Only)
Go to http://127.0.0.1:8000/view-urls.
Log in with the admin credentials.
View the list of URLs stored in the database.
Retraining the Model
After adding a new URL, the model will automatically retrain.
You can also trigger retraining manually by sending a POST request to /retrain.
