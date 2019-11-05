# EVENT DATA COLLECTOR
 Event Data Collector (EDC) is a very basic application used to capture data on the fly. 

It is primarily designed to facilitate the flow of a cohesive red team by enabling both manual and automated collection of operational activities and information. It's not fancy, was designed in stages to meet the need of the hour, and has had some elements removed to protect multiple organizations.

It is expected to be used by only the RT members assigned to the operation and those designated as Trusted Agents (TA), White Cell, or Control Cell members with a need-to-know.

There are options for using S3 storage and enabling the password reset by email feature. Simply uncomment and enter secrets as identified.

## General Info

### App Layout

#### Views
- Info (info): Information about the event
- OPLOG (oplogs) Operator Logs - Log entries of all actions
- Targets (targets): Actioned Targets - Any target asset where actions are performed (succeed or fail)
- Credentials (creds): Obtained Target Credentials - files, mimikatz, keylogging, etc.
- Payloads (payloads): Location for storing pre-made payloads (escalation, c2, peristance, etc.)
- Deconfliction (decon): Deconfliction Data - Basic data, the defensive side should provide more data for verified deconfliction. Note decon is just a subset of oplog data.

#### URLs
- info/
- oplogs/
- targets/
- creds/
- payloads/
- decon/
- tag/ - quick identification of tagged logs (tag/c2)
- user/ - list of logs per operator (user/testerld)


#### Rest Framework API
(Requires IsStaff for access)

- eventinfo/
- oplog/
- cred/
- target/


### Authentication and Authorization

#### Roles
- Lead: Event lead or manager - Has privileges to all edc actions
- Operator: Operator or keyboarder - Has privileges to most edc actions less some permanent delete
- WhiteCell: Has only view privileges for Info and Deconfliction - Trusted Agent, Observer, Data Scientist, etc.

#### Role Permissions
|Permission|Lead|Operator|WhiteCell|
|---|---|---|---|
|add cred|x|x|-|
|view cred|x|x|-|
|change cred|x|x|-|
|delete cred|x|x|-|
|add eventinfo|x|x|-|
|view eventinfo|x|x|x|
|change eventinfo|x|x|-|
|delete eventinfo|x|-|-|
|add oplog|x|x|-|
|view oplog|x|x|-|
|change oplog|x|x|-|
|delete oplog|x|x|-|
|add payload|x|x|-|
|view payload|x|x|-|
|change payload|x|x|-|
|delete payload|x|x|-|
|add target|x|x|-|
|view target|x|x|-|
|change target|x|x|-|
|delete target|x|x|-|
|add decon|x|x|-|
|view decon|x|x|x|
|change decon|x|x|-|
|delete decon|x|-|-|


#### Accounts
It is recommended to remove the default accounts and create new once functionality is confirmed.

- edcadmin:admin pass1 - Superuser
- testerld:user passld - Lead Role
- testerop:user passwc - Operator
- tester1: user pass1 - Operator
- tester2: user pass2 - Operator
- testerwc:user passwc - WhiteCell

##### Account Permissions
|User|Info|Oplog|Targets|Creds|Payload|Deconfliction|
|---|---|---|---|---|---|
|edcadmin|RWD|RWD|RWD|RWD|RWD|RWD|
|testerld|RWD|RWD|RWD|RWD|RWD|RWD|
|testerop|RW|RWD|RWD|RWD|RWD|RW|
|tester1|RW|RWD|RWD|RWD|RWD|RW|
|tester2|RW|RWD|RWD|RWD|RWD|RW|
|testerwc|R|-|-|-|-|R|


#### 2FA
All accounts have the option for 2FA (Authenticator App).
Each account will need to enable 2FA via profile.

### Additional Security Info
- Permission Based Roles
    - Login Required (Decorators or Mixins)
    - Permission Required (Decorator or Mixins)
- Role Based Accounts
    - Lead
    - Operator
    - White Cell
- Individual Accounts (no group or shared accounts)
- Multi-Factor Authentication
    - 2FA Token
- Protections
    - SSL/TLS (Communication Transport)
    - Click Jacking Protection
    - Cross Site Request Forgery Protection
    - Cross Site Scripting Protection
    - Host Header Validation
    - Sessions Security
    - SQL Injection Protection
    - User uploaded content
        - Profile limited to images
            - All users can change respective profiles
        - All other forms allow any file type
            - Allows collection of various file types and interesting information
            - Does not escape or prevent various tags within files (i.e. script)
            - Enables bypass of some XSS and CSRF protections (stored - file)
            - Limited to only Leads and Operators (Trusted Users)
    - Drive or volume encryption recommended (DAR)

---

## Setup

### Host

Install pkgs
```
sudo apt install build-essential autoconf libtool pkg-config python-opengl python-pil python-pyrex python-pyside.qtopengl libpq-dev python3-dev python3-pip postgresql apache2 libapache2-mod-wsgi-py3 python3-venv ufw
```

Enable UFW
```
ufw enable
ufw app list
ufw allow "OpenSSH"
ufw allow "Apache Full"
```

Add to /etc/hosts
- ip domain hostname
```
122.233.144.155 domain.com host1
```

cp files to appropriate locations
```
cd to git dir
sudo cp etc/config.json /etc/.
sudo cp etc/apache2/sites-available/* /etc/apache2/sites-available/.
sudo cp -R edc_app/ /var/www/.
```

Modify the "secrets" config

/etc/config.json
  - modify config
    - key
    - hosts
    - if forgotten password Email used, EMAIL Secretsx2 - otherwise remove
    - if AWS S3, AWS Secretsx3 - if not S3 remove
```
{
    "SECRET_KEY": "move from settings.py",
    "ALLOWED_HOSTS": "'www.domain.com', 'IP Address'",
    "EMAIL_USER": "username",
    "EMAIL_PASS": "password",
    "AWS_STORAGE_BUCKET_NAME": "some-bucket",
    "AWS_ACCESS_KEY_ID": "ID",
    "AWS_SECRET_ACCESS_KEY": "key"
}
```

Modify edc settings per your need
/var/www/edc_app/edc_app/settings.py
 - ALLOWED_HOSTS
 - if forgotten password email used, EMAIL Settings
 - if AWS S3, AWS Settings


### Virtual Environment
Skip to pip requirements now if doing a direct copy

#### Setup venv
Est virtual env
```
python3 -m venv /var/www/edc_app/venv
```

#### Pip Requirements
Install required pkgs in venv
```
source venv/bin/activate
pip3 install -r requirements.txt
```

List of pkgs in pip3 requirements
```
pip3 install django boto3 django-storages django-crispy-forms Pillow django-tables2 django-bootstrap-datepicker-plus djangorestframework djangorestframework-jsonapi django-taggit django-formtools babel django-otp qrcode django-two-factor-auth
```

## Web Server

Modify urls if forgotten password email is used
/var/www/edc_app/edc_app/urls.py
```
Uncomment 4 "path" patterns starting with "password"
```

/etc/apache2/sites-available
- Rename configs to include your domain file names for apache
- modify .conf 
 - Servername
 - Alias
 - SSL

 Backup the domain-ssl config for reference upon ssl config. Note the diffs between the http and https configs, specifically wsgi.

 LetsEncrypt with auto renewal (certbot) works extremely well.


Ensure file permissions
```
sudo chown :www-data /var/www/edc_app/db.sqlite3
sudo chmod 664 edc_app/db.sqlite3
sudo chown :www-data /var/www/edc_app
sudo chown -R :www-data /var/www/edc_app/media/
sudo chmod -R 775 /var/www/edc_app/media
```

If you started a new venv, now would be a good time to collect. If not skip this command.
```
python3 manage.py collectstatic
```

Run a config test and correct any errors
```
sudo apache2ctl configtest
```

Start apache
```
sudo systemctl start apache2
```

Enable site
```
a2ensite yoursite
a2dissite 000-default.conf
```

Reload apache
```
sudo systemctl reload apache2
```

---

## Use:
- Manual entry
- bash_functions (recommend creating binaries in path)
```
    log -h
    cred -h
    target -h
```
- API (curl examples)
```
# Obtain token
curl -d 'username=testerld&password=user passld' https://domain.com/api-token/

# Pull all oplogs (or /cred/ or /target/)
curl https://domain.com/oplog/ -H 'Authorization: Token 333...de8'

# Post a new log entry
curl -d 'src_host=attackimage2&src_ip=44.33.22.11&dst_host=corpwks01&dst_ip=143.144.145.146&dst_port=445&tool=terminal&description=smb_relay&result=success&operator_id=9' https://domain.com/oplog/ -H 'Authorization: Token 333...de8'

```

Note: The bashrc is recommended for use on a user's system as it saves terminal logs locally. It also has several simple example functions for submitting data to EDC. These should be binaries or python execs in your path.

---

## To Do:
- Install script
- Remove redundant pkgs/requirements
- Leverage more templates to reduce the code footprint
- Interactive tables (Modify and DB update)
- Physical Assessment Views (incl. mobile submissions)
- Nested command escapes (and NULL BYTES)