# PyLockr

## Setting up the Virtual Environment on Arch Linux

Some development packages to install

```bash
sudo pacman -S base-devel sqlcipher python-pip python-virtualenv
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


This will install python-dotenv, so i would recommend setting up a .env file which will also be used for docker builds.

Example of the .env file

```bash
APP_SECRET_KEY='opasajcoencoabvoabvrivnrinvfivnslikvnf'
SQLCIPHER_KEY='ExB1KmYIeMNJJ40LsoG6tZlftmUX7YzAehWj/f9MzfY='
FERNET_KEY='TcUTkZN-fPkS1OqVYyG8BjnsIaQWIasDSUwZbgmR5N4='
REDIS_PASSWORD='cjsdbnjkcbsdkjvcbdvsvjbdvsdjblvdjbsjdb'
```

Run the generate_key.py file, which will provide you with some Keys.

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

We set up 3 services and a network to keep the web app services segragated from any other docker instances. In my docker-compose, you will see that I have tried my best to limit each services capability. The only ports exposed will be on the web app itself.

Since this webapp uses SQLCipher, the entire database will be encrypted. The authentican password is hashed, the username is sanitized. All passwords and notes entered into the database go through a second phase of encryption, which is what the FERNET_KEY is for.

```yaml
services:
  web:
    build:
      context: .
      dockerfile: ./dockerfiles/Dockerfile # dockerfile location
    ports:
      - "5000:5000" # expose on these ports
    volumes:
      - ./database:/usr/src/app/database # database available outside container
      - ./backup:/usr/src/app/backup # same for backup
    environment:
      - BACKUP_DIR=/usr/src/app/backup # 
      - DB_PATH=/usr/src/app/database # paths for database
      - SESSION_TIMEOUT=30 # This is when the webapp will timeout the login session
      - MIN_PASSWORD_LENGTH=10 # adjust to suit your needs. This is your authentication password
    env_file:
      - .env # Keys in this file
    depends_on:
      - redis  # Ensure the web service starts after Redis. Used for rate limiting
    networks:
      - pylockr-network # isolate in own network

```


Since we're using SQLCipher, i wanted to utilize the clean backup utility provided, and so hence, we have a scheduler service. This service will create backups on a schedule of your choosing. You will see the environment variables set in the docker-compose file.

```yaml
  scheduler:
    build:
      context: .
      dockerfile: ./dockerfiles/Dockerfile_Scheduler # Has it's own dockerfile
    volumes:
      - ./database:/usr/src/app/database # access to the database outside the app
      - ./backup:/usr/src/app/backup # I would probably mount a network share with redundancy for the backups
    environment:
      - BACKUP_DIR=/usr/src/app/backup # databases will be backed up to this directory
      - DB_PATH=/usr/src/app/database # location of the database
      - MAX_DB_BACKUPS=42 # will retain 42 backups
      - BACKUP_FREQUENCY=240 # will schedule a backup every 240 minutes (keeping 42 backups at 240mins = 1 week worth of backups)
      - SQLCIPHER_KEY=${SQLCIPHER_KEY} # encryption key for the database
    depends_on:
      - redis  # Ensure the scheduler service starts after Redis. Redis is used for rate limiting.
    networks:
      - pylockr-network # isolate with webapp
```

## Redis

There's not a lot to say about the use of this. Except, when you start your docker app, the logs will complain about setting your overcommit memory to 1. This is in the documentation from Redis, and has something to do with forks, and the children unable to sometimes get the memory they need. For myself, I'll be setting this up in a virtual machine, and will likely limit the memory in a redis config, but it will also have allocated virtual machine memory rather than playing with the host system. Not a requirement, but a step i would probably choose to run this the recommended way.

```yaml
  redis:
    image: redis:alpine
    command: redis-server --requirepass ${REDIS_PASSWORD} # A little bit of security by forcing a password
    networks:
      - pylockr-network # isolated in own network

networks:
  pylockr-network:
    driver: bridge # The isolated network
```

## Dockerfiles

The main app dockerfile. I think all the comments and code are self explanatory.

```dockerfile
FROM python:3.11

# Install system dependencies required for pysqlcipher3
RUN apt-get update && apt-get install -y \
    build-essential \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

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

* Installation of sqlcipher. Required to use the commandline for cleanly backing up.
* Copies only the required files necessary
* No exposing

```dockerfile
FROM python:3.11

# Install system dependencies required for pysqlcipher3
RUN apt-get update && apt-get install -y \
    build-essential \
    libsqlcipher-dev \
    sqlcipher \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the application code into the container
COPY ./app/utils/scheduler.py /usr/src/app/app/utils/scheduler.py
COPY ./app/utils/pylockr_logging.py /usr/src/app/app/utils/pylockr_logging.py
COPY ./requirements.txt /usr/src/app/ 
COPY ./scheduler_entry.sh /usr/src/app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Add local user bin directory to PATH
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Specify the entrypoint script
ENTRYPOINT ["./scheduler_entry.sh"]

```

## The Web App

I think navigating around is self explanatory. There are not too many webpages, and not too many bells and whistles. Features included are...

* Capable of importing csv password lists from vaultwarden and Brave browser (guessing chrome as well?) 
* The table uses a fuzzy finder, which is quite a convenient method for searching using the search bar. I have included categories for this purpose, so you can search for 'email' for instance.
* Automatic backups using the scheduling service, as detailed above
* Sanitizing, hashing, double encyption.
* The retrieved passwords table never see's your passwords. The only method of returning your password is while editing, or with the copy to clipboard.
* Download your user passwords. If you decide to move along, or just want a backup, this feature is available. I decided to make sure your passwords were safe by encrypting the CSV with AES-256, in a 7zip archive.

Features i'd like to implement...

* A Commandline interface. I am looking at several options, including...
    - SSH, for remote instances
    - Making it wofi friendly, perhaps with a wofi script.
* Include an NGINX reverse proxy setup, with some security protocols
* Apply more web app security
* A frontpage png that doesn't mention my name...