# webapp

Hi Guys!

Let start cloud assignments in this repo :)

I am using Django REST for the backend

## A01 Description:

- make a health check api:
Check if the application is connected to the database.
Return HTTP 200 OK if the connection is successful.
Return HTTP 503 Service Unavailable if the connection is unsuccessful.
The API response should not be cached. Make sure to add cache-control: 'no-cache' header to the response.
The API request should not allow for any payload. The response code should be 400 Bad Request if the request includes any payload.
The API response should not include any payload.
Only HTTP GET method is supported for the /healthz endpoint.

## Prerequisites for building the Django web application:

Python 3.x installed on your local machine.
Libraries and dependencies using pip: refer requirements.txt
PostgreSQL Database: Install and set up a PostgreSQL database locally.

## Start the App/ Demoing
- download zip and unzip from canvas
- create an dactivate venv: python3 -m venv venv, 
- install dependancies: pip install -r requirements.txt
- python manage.py runserver
- Backend will start at : http://localhost:8000

## Folder Structure
    webapp/
    ├── backend/
    ├── backend_api/
    ├── venv/
    ├── .gitignore
    ├── manage.py
    └── README.md

## Intial data setup and start server:
```sh
1. python3 -m venv venv
2. source venv/bin/activate
3. pip install django djangorestframework
4. pip install psycopg2
5. pip install python-dotenv
6. brew services start postgresql
7. psql -U postgres
8. `CREATE DATABASE webappdb;`
9. django-admin startproject backend .
10. python manage.py startapp backend_api
11. create urls.py inside backend_api
12. in settings.py add:
    DATABASES = {
    'default': {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'your_db_name',
    'USER': 'your_username',
    'PASSWORD': 'your_password',
    'HOST': 'localhost',  # Set to 'localhost' or your server IP
    'PORT': '5432',       # Default PostgreSQL port
    }
    }
13. in settings.py add 'backend_api' in INSTALLED_APPS
14. python manage.py makemigrations
15. python manage.py migrate
16. python manage.py runserver
17. pip freeze > requirements.txt
```

## Developer Details
- Name : Chethana Benny
- Email : benny.c@northeastern.edu