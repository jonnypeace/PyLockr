# PyLockr

A simple password manager written mostly in python using the Flask Library. PyLockr builds with docker have been implemented as the go-to choice for using this application. Users should think carefully about setting this up behind an HTTPS connection, using something like certbot with nginx. I will be detailing these steps in a future README.

## Setting up the Virtual Environment on Arch Linux

Some development packages to install

```bash
sudo pacman -S base-devel python-pip python-virtualenv
```

At this point, I use vscode and use a ctrl+p and search for env to set up a virtual environment, but I believe the same can be achieved from the terminal...

```bash
python -m venv venv_name
source venv_name/bin/activate
```

Then install from the requirements

```bash
pip install -r requirements.txt
```


I would recommend setting up a .env file which will also be used for docker builds, it's also quite a practical approach for this type of environment.

Example of the .env file

```bash
APP_SECRET_KEY='191d8e6d72233434418d31088664018e1af501df9b5058d189ea2a8c2d1187ac'

# Used to encrypt data before entering to DB
FERNET_KEY='3_MJgj_CtyH0-nXcAHzIElI1ceQ_9kR_6pu8bGzRnG0='

# Used for redis, which keeps track of rate limiting
REDIS_PASSWORD='tU_6sT!RCugPA:ADRU:V%sT3y50k4wf9'

# Big long root password for mariadb
MYSQL_ROOT='gc8_fFc%-_nvXq#h4ZX-0_y-l^1m8boI'

# mariadb user password
MYSQL_PASSWORD='rFCVse:u9InaOxoOCkinVopRvuf5OrwY'

# GPD passphrase for symmetric encryption of the mariadb backups
GPG_PASSPHRASE='9YbODuLQT#DrbZ-F&KQC-UnyCaptFOf#'


MYSQL_USER='username'

# Location for the mariadb configs for ssl network communication, encryption key, and custom config
DB_KEY_DIR='config/keys'
DB_CNF_DIR='config/cnf'
DB_SSL_DIR='config/ssl'

# more database config
MYSQL_DB=pylockrdb
MYSQL_HOST=mariadb
MYSQL_PORT=3306

# SSL Configuration
SSL_CA=/usr/src/app/ssl/ca-cert.pem
SSL_CERT=/usr/src/app/ssl/client-cert.pem
SSL_KEY=/usr/src/app/ssl/client-key.pem

# Database connection string with SSL parameters
DB_PATH="mariadb+mariadbconnector://${MYSQL_USER}:${MYSQL_PASSWORD}@${MYSQL_HOST}:${MYSQL_PORT}/${MYSQL_DB}?ssl_ca=${SSL_CA}&ssl_cert=${SSL_CERT}&ssl_key=${SSL_KEY}"

SECURE_COOKIE_HTTPS=true
TRUSTED_DOMAIN='laptop.home'
```

Run the generate_key.py file, which will provide you with some Keys.

There is also a setup.sh bash script which will generate the ssl keys in a path called config in the root directory of the app.

## Docker Builds

First of all, you'll need docker, docker-compose...

```bash
sudo pacman -S docker-compose docker
```

Check the status, and enable docker if needed..

```bash
sudo systemctl status docker
sudo systemctl enable --now docker
sudo systemctl status docker
```

Add user to docker group
```bash
sudo usermod -aG docker $USER
```

At this point you'll need to log out and back in for the user group to work.

You should be able to build from the dockerfile, and docker-compose file provided.

```bash
docker-compose build --no-cache
```

You can add a -d to the end of this command to detach, but for debugging I leave myself attached

```bash
docker-compose up
```

## Web App Capabilities

This web app has been designed to do several things, mostly automatically where possible.

We set up 4 services and a network to keep the web app services segragated from any other docker instances. In my docker-compose, you will see that I have tried my best to limit each services capability. The only ports exposed will be on the web app itself. In a future version, i may provide an option to expose the mariadb ports so we can tap into the database with a desktop script, using wofi or demnu.

Since this webapp will be using Key Encryption for Encryption at rest, the entire database will be encrypted. I have supplied a script to generate the keys and SSL certs, and config so mariadb can be safely communicated with over a network. The user authentication password is hashed, the username is sanitized. All passwords and notes entered into the database go through a second phase of encryption, which is what the FERNET_KEY is for.


```yaml

services:
  web:
    build:
      context: .
      dockerfile: ./dockerfiles/Dockerfile
    volumes:
      - ./backup:/usr/src/app/backup
      - ./config/ssl:/usr/src/app/ssl # Encryption keys
    environment:
      - BACKUP_DIR=/usr/src/app/backup
      - SESSION_TIMEOUT=30
      - MIN_PASSWORD_LENGTH=10
    env_file:
      - .env
    depends_on:
      - redis
      - mariadb  # Ensure the web service starts after MariaDB is ready
    networks:
      - pylockr-network

```

## Backup Scheduler

Since we're using maraidb, i wanted to utilize a clean backup utility, and so hence, we have a scheduler service. This service will create backups on a schedule of your choosing. You will see the environment variables set in the docker-compose file. The purpose of the GPG_PASSPHRASE in the .env, is so that you end up with gpg encrypted backups. Again, highlighting the importance of keeping your keys/passwords somewhere safe.

The scheduler needs access to the ssl encryption keys for safe communication to the mariadb server.

This example keeps backups for a week (42 backups, backup every 240mins)

```yaml

  scheduler:
    build:
      context: .
      dockerfile: ./dockerfiles/Dockerfile_Scheduler
    volumes:
      - ./backup:/usr/src/app/backup
      - ./config/ssl:/usr/src/app/ssl # Encryption keys
    environment:
      - BACKUP_DIR=/usr/src/app/backup
      - MAX_DB_BACKUPS=42
      - BACKUP_FREQUENCY=240
      - RUN_SCHEDULER=true
    env_file:
      - .env
    depends_on:
      - redis
      - mariadb  # Ensure the scheduler service starts after MariaDB is ready
    networks:
      - pylockr-network
```

## Redis

When you start your docker app, the logs will complain about setting your overcommit memory to 1. This is in the documentation from Redis, and has something to do with forks, and the children unable to sometimes get the memory they need. Consider setting this up in a virtual machine with the overcommit memory set to 1. This will ensure the host system doesn't run into memory issues. Not a requirement, but a step i would probably choose to run this the recommended way.


```yaml
  redis:
    image: redis:alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    networks:
      - pylockr-network

```

## MariaDB

MariaDB is where your user authentication and password management data is stored. The volume at the bottom ensures persistent storage between docker restarts, and rebuilds. To clear the volume, you can

```bash
docker-compose down -v
```


I think most of the environment variables set here are quite clear. You can see the config directory after you've run setup.sh, will be mapped to /etc/sql locations for mariadb to read from.

```yaml

  mariadb:
    image: mariadb:latest
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_ROOT}
      - MYSQL_USER=${MYSQL_USER}
      - MYSQL_PASSWORD=${MYSQL_PASSWORD}
      - MYSQL_DATABASE=pylockrdb
    volumes:
      - mariadb_data:/var/lib/mysql
      - ./config/cnf:/etc/mysql/conf.d  # Custom my.cnf
      - ./config/ssl:/etc/mysql/ssl  # SSL Encryption keys
      - ./config/keys:/etc/mysql/encryption  # Data at Rest Encryption key

    networks:
      - pylockr-network
```

## NGINX

```yaml
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./config/nginx/ssl:/etc/ssl/private:ro
    depends_on:
      - web
    networks:
      - pylockr-network

networks:
  pylockr-network:
    driver: bridge

volumes:
  mariadb_data: {}

```

### nginx config

Change the laptop.home server names so the server name / domain of your choosing

```bash
# Server block for HTTP - Listen on port 80
server {
    listen 80;
    server_name laptop.home;
    return 301 https://$host$request_uri;  # Redirect HTTP to HTTPS
}

# Server block for HTTPS - Listen on port 443
server {
    listen 443 ssl;
    server_name laptop.home;

    ssl_certificate /etc/ssl/private/fullchain.pem;  # Path to your SSL certificate
    ssl_certificate_key /etc/ssl/private/privkey.pem;  # Path to your SSL private key

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    location / {
        proxy_pass http://web:5000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```


## Dockerfiles

The main app dockerfile. I think all the comments and code are self explanatory.

```dockerfile

FROM python:3.11

RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the application code into the container
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Add local user bin directory to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Use Entrypoint for shells

ENTRYPOINT ["./entry.sh"]

```

Scheduler dockerfile. The main difference here are...

* Installation of mariadb client. Required to use the commandline for cleanly backing up.
* Copies only the required files necessary
* No exposing

```dockerfile

FROM python:3.11

# Install system dependencies required for mariadb
RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-client \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the application code into the container
COPY ./app/utils/scheduler.py /usr/src/app/app/utils/scheduler.py
COPY ./app/utils/pylockr_logging.py /usr/src/app/app/utils/pylockr_logging.py
COPY ./scheduler_entry.sh /usr/src/app/

# Install any needed packages specified in requirements.txt
RUN pip install APScheduler 

# Add local user bin directory to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Specify the entrypoint script
ENTRYPOINT ["./scheduler_entry.sh"]

```

## Using Cloudflare API with docker

Add this to your config/nginx/cloudflare.ini

```bash
# Cloudflare API token
dns_cloudflare_api_token = 0123456789abcdef0123456789abcdef01234567

# OR, if using email and Global API Key:
#dns_cloudflare_email = your_email@example.com
#dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234567
```

```bash
chmod 600 cloudflare.ini
```

Use DNS challenge if self hosting without opening ports

```bash
docker run -it --rm \
    -v "./config/nginx/cloudflare.ini:/etc/letsencrypt/cloudflare.ini" \
    -v "./config/nginx/ssl:/etc/letsencrypt" \
    certbot/dns-cloudflare certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d "example.com" -d "*.example.com"
```
### renewal

Set this up in a cronjob.

```bash
docker run -it --rm \
    -v "./config/nginx/cloudflare.ini:/etc/letsencrypt/cloudflare.ini" \
    -v "./config/nginx/ssl:/etc/letsencrypt" \
    -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
    certbot/dns-cloudflare renew
```

## Snakeoil Certs

I would just send the keys directly to the config/nginx/ssl directory if you follow my setup

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /path/to/your/privkey.pem -out /path/to/your/fullchain.pem

# req: Command to manage certificate signing requests (CSR).
# -x509: Generates a self-signed certificate.
# -nodes: Stores the private key without passphrase protection.
# -days 365: Sets the certificate to expire after one year. You can adjust this as needed.
# -newkey rsa:2048: Generates a new certificate request and a new private key. rsa:2048 specifies an RSA key 2048 bits in length.
# -keyout: Specifies the filename to write the newly created private key to.
# -out: Specifies the output filename for the newly created certificate.

```

## The Web App

I think navigating around is self explanatory. There are not too many webpages, and not too many bells and whistles. Features included are...

* Capable of importing csv password lists from vaultwarden, firefox and Brave browser (guessing chrome as well?) 
* The table has a useful search box, which is quite a convenient method for searching using the search bar. I have included categories for this purpose, so you can search for 'email' for instance.
* Automatic backups using the scheduling service, as detailed above
* Sanitizing, hashing, double encyption of passwords, use of an ORM for mariadb.
* The retrieved passwords datatable never see's your passwords. The only method of returning your password is while editing, or with the copy to clipboard.
* Download your user passwords. If you decide to move along, or just want a backup, this feature is available. I decided to make sure your passwords were safe by encrypting the CSV with AES-256, in a 7zip archive.
* HTTPS configured in Flask and NGINX, if you follow my configuration.
* CSRF tokens on each request
* Session token expiry (cookie expiry)
* Nonce token with CSP for safe javascript useage and styling
* CDN files hashed and checked

Features i'd like to implement...

* A Commandline interface. I am looking at several options, including...
    - SSH, for remote instances
    - Making it wofi friendly, perhaps with a wofi script.

If there are features you'd like to see, i welcome feedback and contributions.

Limitations...

* Testing. I'm one person, learning as I go.
* Uncertain how imports from other password managers will work. Only tested with Brave browser, firefox and Vaultwarden
* Documentation. This might take some time to get right, but it is a simple web app, and hopefully i've explained most of it.
* No 2FA. I've been on the fence with this, but it's probably needed. I have planned to use this behind wireguard, in isolation, behind reverse proxies etc etc. Not everyone will do this though, so if you really want this let me know.

### Contact Details

If you would like to help, contribute, provide feedback (good or bad), I will always be willing to listen. Feel free to raise Github issues.

You can get me on jonnypeace@outlook.com (but i will warn you, i'm a busy person)
