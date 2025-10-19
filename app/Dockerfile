FROM python:3.12.3-slim

# Install Apache + mod_wsgi + dependencies
RUN apt-get update && apt-get install -y \
    apache2 \
    apache2-dev \
    build-essential \
    libapache2-mod-wsgi-py3 \
    php \
    libapache2-mod-php \
    sudo \
    nano \
    && apt-get clean \
    && a2enmod php8.2

# Créer un environnement virtuel
RUN python3 -m venv /var/www/html/venv


RUN apt-get update && apt-get install -y openssh-server

# Mettre à jour pip dans l'environnement virtuel
RUN /var/www/html/venv/bin/pip install --upgrade pip

# Copier le fichier requirements
COPY requirement.txt /var/www/html/

# Installer les dépendances Python (une seule fois)
RUN /var/www/html/venv/bin/pip install -r /var/www/html/requirement.txt

# Copier l'application
COPY . /var/www/html

RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html
RUN mkdir -p /var/www/html/instance

# Créer un utilisateur SSH (optionnel)
RUN useradd -ms /bin/bash admin \
    && echo 'admin:admin' | chpasswd \
    && usermod -aG sudo admin \
    && echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
# Créer le répertoire SSH
RUN mkdir /var/run/sshd


RUN chown -R www-data:www-data /var/www/html/instance
RUN chmod -R 777 /var/www/html/instance

# Copier la config Apache
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf


#donner les droits d'écriture seulement à root 
# Changer le propriétaire
RUN chown root:root /var/www/html/Dockerfile

# Changer les permissions
RUN chmod 600 /var/www/html/Dockerfile


# Activer mod_wsgi
RUN a2enmod wsgi




# Exposer le port
EXPOSE 80 22


#CMD service ssh start 
# Lancer Apache en mode foreground
CMD service ssh start  &&  apachectl -D FOREGROUND