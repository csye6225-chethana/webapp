# webapp

Hi Guys!

Let start cloud assignments in this repo :)

I am using Django & PostgreSQL for the backend.
test

## [A01 Health Check RESTful API](https://northeastern.instructure.com/courses/192916/assignments/2459288)

- Check if the application is connected to the database.
- Return HTTP 200 OK if the connection is successful.
- Return HTTP 503 Service Unavailable if the connection is unsuccessful.
- The API response should not be cached. Make sure to add cache-control: 'no-cache' header to the response.
- The API request should not allow for any payload. The response code should be 400 Bad Request if the request includes any payload.
- The API response should not include any payload.
- Only HTTP GET method is supported for the /healthz endpoint.

## [A02 Web Application Development](https://northeastern.instructure.com/courses/192916/assignments/2463019) 

- Bootstrap the database at startup automatically
- Implement create user, get user and update user apis
- Should implement basic http authentication for get and update
- Write unit tests

## [A03 AWS setup, Continuous Integration](https://northeastern.instructure.com/courses/192916/assignments/2463019) 

- AWS
    1. Organisation setup
    2. IAM setup
    3. AWS cli
    4. Infra setup through Terraform
- CI
    - Github branch protection Rules
    - Github Actions workflow

## Prerequisites for building the Django web application:

- Python 3.x 
- pip package installer
- Libraries and dependencies installed [(refer requirements.txt)](requirements.txt)
- PostgreSQL Database 

## Start the App on local/ Demoing
- download zip and unzip folder from canvas
- create and activate venv:
    - `python3 -m venv venv` 
    - `source venv/bin/activate`
- install dependancies: `pip install -r requirements.txt`
- make sure db is running: `brew services start postgresql`
- Start the server: `python manage.py runserver`
- Backend will start at : http://localhost:8000

## Folder Structure
    webapp/
    ├── backend/
    ├── backend_api/
    ├── venv/
    ├── .gitignore
    ├── manage.py
    └── README.md

## Intial setup and start server on local:
1. PostgreSQL db setup
    ```
    brew services start postgresql
    psql -U postgres
    `CREATE DATABASE webappdb;`
    ```
2. Django backend setup
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip install django djangorestframework
    pip install psycopg2
    pip install python-dotenv
    pip freeze > requirements.txt
    django-admin startproject backend .
    python manage.py startapp backend_api
    ```
    In settings.py update DATABASES and INSTALLED_APPS:
    ```
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
    ```
    - add 'backend_api' in INSTALLED_APPS
3. Run Server
    ```
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runserver
    ```

## Remote VM setup on digital ocean:
1. Create a droplet(vm) on Digital Ocean.
2. Generate an ssh key pair and add public key in digital ocean
3. Add public ip of vm in ssh config as hostname and name host as say 'digitalocean' :
    cd ~/.ssh
    vi config
    ```
    # Digital ocean ubuntu droplet
    Host digitalocean
        HostName 143.198.187.155
        User root
        IdentityFile ~/.ssh/id_ed25519_digitalocean
        IdentitiesOnly yes
    ```
4. In vm console: `mkdir cloud`
5. From local, scp the code folder and the setup file into vm: 
`scp "/Users/chethanabenny/Documents/NEU Coursework/Cloud/demo/webapp.zip" "/Users/chethanabenny/Documents/NEU Coursework/Cloud/demo/setup.sh" digitalocean:/root/cloud`
6. In vm, cd webapp and create .env and paste contents there
7. cd .. and run the setup script: `bash setup.sh`
8. If 7 doesnt work, run each step manually. In vm console:
    ```
    sudo apt install
    sudo apt upgrade

    sudo apt install python3
    apt install python3-pip

    apt install unzip
    unzip webapp.zip

    <!--  postgres setup -->
    sudo apt install postgresql
    sudo -i -u postgres
    psql
    ALTER USER postgres WITH PASSWORD 'singapore';
    CREATE DATABASE webappdb;

    <!-- setup virtual env -->
    apt install python3.12-venv
    python3 -m venv venv
    source venv/bin/activate

    <!-- install libraries and dependencies -->
    pip install -r requirements.txt
    sudo apt-get install libpq-dev
    pip install -r requirements.txt

    <!-- run sremote erver -->
    python3 manage.py makemigrations
    python3 manage.py runserver 0.0.0.0:80000
    ```


## Developer Details
- Name : Chethana Benny
- Email : benny.c@northeastern.edu