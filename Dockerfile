FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Mise à jour + installation des dépendances
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    libapache2-mod-php \
    python3 \
    python3-pip \
    openssh-server \
    curl \
    net-tools \
    nano \
    sudo \
    iputils-ping \
    && apt-get clean

# Installer Flask et autres dépendances Python

# Ajouter un utilisateur SSH (optionnel)
RUN useradd -ms /bin/bash web && echo 'web:web' | chpasswd && adduser web sudo

# Créer le répertoire SSH
RUN mkdir /var/run/sshd

# Déployer l'application Flask
WORKDIR /var/www/html/app

# Copier les fichies dans le conteneur Docker
COPY . /var/www/html/app

# Déployer les fichiers PHP vulnérables ou autres fichiers dans Apache
RUN chmod -R 755 /var/www/html/

# Créer un environnement virtuel Python et installer les dépendances
RUN python3 -m venv venv
RUN . venv/bin/activate && pip install --upgrade pip && pip install --no-cache-dir -r /var/www/html/app/requirement.txt


# Config Apache pour supporter PHP
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
RUN a2enmod php8.1


# Exposer les ports nécessaires
EXPOSE 80 5000 22

# Commande de démarrage : Apache, SSH et Flask
CMD service ssh start && service apache2 start && . venv/bin/activate && python /var/www/html/app/app.py
