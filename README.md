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


