import sys
import logging
import os

# Ajoute les bons chemins
venv_path = '/var/www/html/venv'
python_home = os.path.join(venv_path, 'lib/python3.12/site-packages')

# Injecte les paquets du venv
sys.path.insert(0, python_home)
sys.path.insert(0, '/var/www/html')

from app import app as application  # mod_wsgi attend "application"

logging.basicConfig(stream=sys.stderr)
