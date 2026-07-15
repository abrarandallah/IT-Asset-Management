# Intelligent IT Asset Management System

A Django-based tool for:

- Asset discovery (mock or real via Nmap)
- Risk scoring based on CVEs and age
- Lifecycle tracking (warranty & replacement)
- Simple reporting (JSON export)

## Features

✅ Network scanning (Nmap or mock)  
✅ Admin dashboard  
✅ Risk analysis  
✅ Lifecycle tracking  
✅ JSON report export

## Setup

1. Clone the repo and open a terminal in the project folder
2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   venv\Scripts\activate        # Windows
   source venv/bin/activate     # macOS/Linux
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and set your own `DJANGO_SECRET_KEY` (generate one with the command inside the file)
4. Run migrations and create your own admin account:
   ```
   python manage.py migrate
   python manage.py createsuperuser
   python manage.py runserver
   ```
5. (Optional) Load demo data to explore the app with realistic sample assets:
   ```
   python fake_asset_generator.py
   ```
   This adds randomly generated fake devices and scan logs — safe to run multiple times to add more variety. To also populate fake vulnerability data for risk-scored assets, run:
   ```
   python add_fake_vulnerabilities.py
   ```

## Admin Access

Log in at `/admin/` using the superuser account you create in step 4 above.
No default credentials are shipped with this project.