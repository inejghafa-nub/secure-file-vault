# Intelligent Secure File Vault

A Flask-based academic project for encrypted file storage and dynamic access control.

## Features

- User registration and login
- Strong password validation during registration
- Separate user login and host login
- Password hashing with Werkzeug
- AES encryption before file storage
- Owner-only file downloads
- Secure share links with expiry time
- Download limits for shared files
- Share link management and revoke option
- Delete encrypted files and related links
- Change password for users and host
- Cyber secure visual theme
- File search by filename
- File size, type, and download-count tracking
- Failed login monitoring in the host dashboard
- Activity logs for uploads, downloads, sharing, and login
- Host dashboard for users, files, share links, and logs
- SQLite database for users, file metadata, share links, and logs

## Run The Project

```powershell
cd C:\file-vault
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Demo Host Account

- Username: `host`
- Password: `Host@12345`

## Suggested Demo Flow

1. Register a new user.
2. Login to the dashboard.
3. Upload any file and explain that it is encrypted before storage.
4. Download the file as the owner.
5. Generate a share link with expiry and download limit.
6. Open the share link and show that the download counter is enforced.
7. Visit Activity Logs to show auditing.
8. Login as host and show the monitoring dashboard.
9. Revoke a share link and delete a file from the user dashboard.
10. Change the account password using the strong password rules.

## Project Modules

- `app.py`: Flask routes and application workflow
- `models.py`: Database models
- `encryption.py`: AES encryption and decryption helpers
- `templates/`: User interface pages
- `static/style.css`: Application styling
- `uploads/`: Encrypted file storage
