# Password Den

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
MIN_PASSWORD_LENGTH='12'
APP_SECRET_KEY='What-A-Jolly_Golly_PASSword_App_Yall'
SESSION_TIMEOUT='30'
SQLCIPHER_KEY='ExB1KmYIeMNJJ40LsoG6tZlftmUX7YzAehWj/f9MzfY='
FERNET_KEY='TcUTkZN-fPkS1OqVYyG8BjnsIaQWIasDSUwZbgmR5N4='
```

Run the generate_key.py file, which will provide you with a Fernet Key and SQLCIPHER Key

