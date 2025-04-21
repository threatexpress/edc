Refactor of the original EDC

## Install and setup
Copy files to your run location

Start a venv and install requirements
```
python3 -m venv venv
source venv/bin/activate

pip install django
pip install Pillow
pip install djangorestframework
```

Initialze the server
```
python manage.py makemigrations collector
python manage.py migrate
```
Create a user if required
```
python manage.py createsuperuser

```

Start the server
```
python manage.py runserver
```

### API
```
# Get Token
curl -X POST http://127.0.0.1:8000/api/get-token/ \
     -H 'Content-Type: application/json' \
     -d '{ "username": "op1", "password": "op1_password" }'

# Test Token
curl -X GET http://127.0.0.1:8000/collector/api/oplog/ \
     -H 'Authorization: Token <YOUR_TOKEN_STRING>'

# POST via TOKEN
curl -X POST http://127.0.0.1:8000/collector/api/oplog/ \
     -H 'Content-Type: application/json' \
     -H 'Authorization: Token <YOUR_TOKEN_STRING>' \
     -d '{
           "command": "ipconfig /all (via token)",
           "output": "Windows IP Configuration...",
           "notes": "Testing API POST with Token",
           "target_id": 1
         }'

     ## Target Fields
     ip_address
     hostname
     operating_system
     users
     description

     ## Credential Fields
     service
     username
     password_plaintext
     hash_value
     hash_type
     notes

     # Oplog Fields
     target
     dst_port
     dst_host
     src_ip
     src_port
     src_host
     url
     tool
     command
     output
     notes
     screenshot (file)
     sys_mod
     enum (file)

     # Enumeration Fields
     target
     scan_type
     description
     notes
     scan_file (file)

     # Payload Fields
     name
     description
     payload_type
     file

     #Exfil Fields
     oplog_entry
     file
     description

```

### API Urls (Browseable)
- http://127.0.0.1:8000/api-auth/login/
- http://127.0.0.1:8000/collector/api/oplog/
- http://127.0.0.1:8000/collector/api/targets/
- http://127.0.0.1:8000/collector/api/credentials/
- http://127.0.0.1:8000/collector/api/payloads/
- http://127.0.0.1:8000/collector/api/enumdata/

#### GET via SESSION
```
# Replace cookie values with ones from your browser's developer tools after logging in

curl -X GET http://127.0.0.1:8000/collector/api/oplog/ \
     -H 'Accept: application/json' \
     -H 'Cookie: sessionid=YOUR_SESSION_ID; csrftoken=YOUR_CSRF_TOKEN' \
     -H 'X-CSRFToken: YOUR_CSRF_TOKEN'
```

#### POST via SESSION
```
# Replace cookie/CSRF values
curl -X POST http://127.0.0.1:8000/collector/api/oplog/ \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -H 'Cookie: sessionid=YOUR_SESSION_ID; csrftoken=YOUR_CSRF_TOKEN' \
     -H 'X-CSRFToken: YOUR_CSRF_TOKEN' \
     -d '{
           "command": "whoami (via curl)",
           "output": "nt authority\\system",
           "notes": "Testing API POST",
           "target_id": 1
         }'
```
---

# If starting a new project. CAUTION: This reinitializes files
```
django-admin startproject <project_name> .
python manage.py startapp collector
python manage.py makemigrations collector
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver