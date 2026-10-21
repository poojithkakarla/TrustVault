
# TrustVault

## About the Project
TrustVault is a secure document-sharing application built with Python, Flask, and SQLite.

It helps users upload, view, and share documents with access permissions.

## Features
- User login and authentication
- Role-based access for Admin, Owner, and Viewer
- Document upload and viewing
- Document sharing with selected viewers
- Revoke document access
- Audit logs for document activities
- SQLite database for storing application data

## Technologies Used
- Python
- Flask
- SQLite
- HTML
- CSS

## Project Structure
- `app.py` - Flask application and routes
- `database.py` - Database setup and functions
- `create_user.py` - Create owner and viewer accounts
- `templates/` - HTML templates
- `static/` - Static files such as CSS
- `uploads/` - Uploaded documents
- `THREATS.md` - Security threat model
- `PROMPTS.md` - AI usage log

## How to Run

1. Install Python.
2. Open a terminal in the project folder.
3. Install the required packages:

   `pip install flask`

4. Initialize the database if required:

   `python database.py`

5. Start the application:

   `python app.py`

6. Open this address in your browser:

   `http://127.0.0.1:5000`

## Security Notes
- Test access permissions using different user roles.
- Verify that revoked users cannot access documents.
- Do not upload real confidential documents.
- Do not commit passwords, secret keys, or sensitive data to GitHub.

## Documentation
See `THREATS.md` for identified security threats and `PROMPTS.md` for the AI usage log.
