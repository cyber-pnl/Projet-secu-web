# Projet-secu-web

Résumé
-----
Ce dépôt contient le projet académique "Projet-secu-web" : un site web volontairement vulnérable créé dans le but pédagogique de comprendre, exploiter et corriger des failles de sécurité web. L'objectif est d'apprendre les concepts d'attaque et de défense dans un environnement contrôlé.

Important — usage et éthique
---------------------------
- Ce dépôt est strictement destiné à un usage éducatif, dans un environnement isolé (VM / réseau local / labo).  
- N'utilisez pas les techniques expliquées ici contre des systèmes dont vous n'avez pas l'autorisation explicite.  
- L'auteur et les contributeurs ne sont pas responsables de l'usage malveillant des informations fournies.

Objectifs pédagogiques
----------------------
- Construire et analyser une application web classique (frontend + backend + stockage).  
- Identifier et exploiter des vulnérabilités courantes (XSS, SQLi, CSRF, IDOR, upload non sécurisé, etc.).  
- Implémenter et vérifier des correctifs pour chacune des vulnérabilités.  
- Documenter les découvertes et les remédiations.

Stack (exemple)
---------------
Le projet peut utiliser l'une des stacks suivantes (adapter selon le dépôt réel) :
- Backend : Node.js (Express) ou Python (Flask / Django)
- Frontend : HTML/CSS/JS simples
- Base de données : SQLite / MySQL
- Conteneurisation : Docker (optionnel)

Modifiez les sections d'installation/usage si votre dépôt utilise une stack différente.

Contenu du dépôt
----------------
- /app ou /src — code de l'application (frontend + backend)  
- /db — scripts ou dumps de base de données pour l'environnement de test  
- /vulns — exemples, payloads, scripts de test (facultatif)  
- /patches — correctifs appliqués pour chaque vulnérabilité  
- README.md — document d'usage et d'explication (ce fichier)  
- docs/ — rapports, captures d'écran, journal des tests (recommandé)

Prérequis
---------
- Git
- Docker & docker-compose (fortement recommandé pour isoler l'environnement)
- Node.js >= LTS / Python >= 3.8 si vous exécutez localement sans conteneurs
- Outils de test de sécurité (optionnel) : OWASP ZAP, Burp Suite, sqlmap, nikto, curl

Installation (avec Docker)
--------------------------
1. Cloner le dépôt :
   git clone https://github.com/cyber-pnl/Projet-secu-web.git
2. Se placer dans le dossier :
   cd Projet-secu-web
3. Lancer les services :
   docker-compose up --build
4. Accéder à l'application :
   Ouvrir http://localhost:8080 (port à adapter selon le docker-compose)

Installation (sans Docker — exemple générique)
----------------------------------------------
1. Installer les dépendances du backend :
   - Node.js (ex.) : npm install
   - Python (ex.) : pip install -r requirements.txt
2. Initialiser la base de données (consulter /db pour scripts)
3. Lancer le serveur :
   - Node.js : npm start
   - Python : python app.py
4. Ouvrir le navigateur sur http://localhost:8000 (port à adapter)

Comment travailler avec le projet
--------------------------------
- structurez vos tests dans /vulns/tests-<nom_vuln>  
- documentez vos étapes d'exploitation et de patch dans /docs ou /patches  
- maintenez une branche "vulnerable" (application vulnérable) et une branche "patched" (correctifs appliqués) pour comparaison et revue de code

Vulnérabilités incluses (exemples et recommandations)
----------------------------------------------------
Ce dépôt a été conçu pour exposer plusieurs vulnérabilités courantes. Ci-dessous des descriptions générales, méthodes de détection et corrections recommandées.

1) Injection SQL (SQLi)
- Présentation : entrées utilisateur insérées directement dans des requêtes SQL.
- Détection : entrées provoquant erreurs SQL, utilisation d'outils comme sqlmap.
- Correctif recommandé : requêtes paramétrées / ORM, validation/échappement des entrées, principe du moindre privilège pour la base.

2) Cross-Site Scripting (XSS)
- Présentation : insertion de scripts malveillants dans les pages affichées.
- Détection : payloads simples (<script>alert(1)</script>), scanners comme OWASP ZAP.
- Correctif recommandé : échappement/encodage des sorties, CSP (Content Security Policy), validation côté serveur.

3) Cross-Site Request Forgery (CSRF)
- Présentation : requêtes malveillantes initiées par l'utilisateur authentifié.
- Détection : absence de token CSRF sur formulaires/actions sensibles.
- Correctif recommandé : ajouter des tokens CSRF anti-rejeu, vérifier Origin/Referer.

4) Insecure Direct Object Reference (IDOR)
- Présentation : accès direct à des ressources par identifiants manipulables.
- Détection : modification d'IDs dans l'URL pour accéder à des ressources d'autres utilisateurs.
- Correctif recommandé : vérifier les droits d'accès côté serveur avant de renvoyer des ressources.

5) Upload de fichiers non sécurisé
- Présentation : upload permettant l'exécution de code ou l'accès à la FS.
- Détection : upload de fichiers .php/.jsp ou scripts et exécution.
- Correctif recommandé : contrôle strict des types, stockage hors webroot, renommage, analyse antivirus.

6) Command Injection
- Présentation : construction de commandes shell avec entrées utilisateur.
- Détection : comportements anormaux après saisie de caractères spéciaux.
- Correctif recommandé : éviter l'appel de shell, utiliser API sans interpréteur, valider/filtrer strictement.

7) SSRF (Server-Side Request Forgery)
- Présentation : serveur effectue des requêtes arbitraires (ex : accès à metadata service).
- Détection : possibilité d'initier des requêtes vers des URLs arbitraires.
- Correctif recommandé : whitelist d'hôtes, vérifier/sanitiser les URL, limiter les connexions sortantes.

Notes sur l'exploitation et les tests
-------------------------------------
- Exécutez les tests dans un environnement isolé.  
- Documentez chaque exploitation : payload, réponse attendue, impact.  
- Favorisez des tests automatisés dans /vulns/tests-... pour reproductibilité.  
- N'incluez pas d'outils intrusifs sur des environnements partagés sans autorisation.

Guide de correction (workflow suggéré)
-------------------------------------
1. Reproduire la vulnérabilité et documenter (captures, payloads).  
2. Proposer un ou plusieurs correctifs dans /patches/<nom_vuln>.  
3. Implémenter le correctif sur une branche dédiée.  
4. Écrire des tests de non-régression (unitaires/functional) pour couvrir le cas.  
5. Revoir et merger quand validé.

Bonnes pratiques de sécurité à intégrer
--------------------------------------
- Validation côté serveur + côté client
- Principe du moindre privilège (DB / fichiers / comptes)
- Gestion sécurisée des sessions (secure, HttpOnly, SameSite)
- Chiffrement des données sensibles en transit (HTTPS) et au repos si nécessaire
- Journalisation et monitoring des activités suspectes

Contribuer
----------
- Ouvrez une issue pour proposer des vulnérabilités supplémentaires, des corrections ou des améliorations de documentation.  
- Faites des Pull Requests claires : description, étapes pour reproduire, tests ajoutés, risques potentiels.

Licence
-------
Indiquez ici la licence choisie (ex : MIT, CC-BY-SA). Si projet académique, préciser les conditions de réutilisation.

Auteurs et contacts
-------------------
- Auteur principal : [Votre nom / pseudo]  
- Contact : [email ou autre moyen]  
- Équipe pédagogique / encadrant : [Nom(s)]

Ressources utiles
-----------------
- OWASP Top 10 — https://owasp.org/www-project-top-ten/  
- Web Security Academy — https://portswigger.net/web-security  
- Documentation officielle des frameworks utilisés (Express, Django, etc.)

Remarques finales
-----------------
Ce README est une base. Adaptez-le au contenu réel du dépôt : précisez la stack exacte, la procédure d'installation, les ports et les scripts disponibles. Documentez chaque vulnérabilité présente dans le code avec les preuves d'exploitation et les correctifs appliqués pour garder une traçabilité pédagogique complète.
