from flask import Flask, render_template, redirect, url_for, flash, request, send_file,jsonify,abort, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os , io
from models import db, Task, User, File 
from werkzeug.utils import secure_filename
from sqlalchemy import text
import secrets
from datetime import datetime, timedelta , timezone
from flask_wtf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Empêche l'accès depuis JavaScript
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

""" app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER']) """

# Définir les extensions autorisées
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx','zip', 'csv','xlsx','ppt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def generate_random_filename(original_filename):
    ext = os.path.splitext(original_filename)[1]  # récupère l'extension (.pdf, .png...)
    return secrets.token_hex(16) + ext  # nom aléatoire + extension
####commentaire
@login_manager.user_loader
def load_user(user_id):
    from models import User

    return User.query.get(int(user_id))

@app.route('/')
def accueil():
    return redirect("/login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    import re, time, random
    import bleach
    # Protection CSRF
    if request.method == 'POST':
        # Récupération des données avec validation
        try:
            nom = bleach.clean(request.form['nom'].strip())
            prenom = bleach.clean(request.form['prenom'].strip())
            date_naissance = request.form['date_naissance']
            email = bleach.clean(request.form['email'].strip().lower())
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            # Validation des champs
            if not all([nom, prenom, date_naissance, email, password, confirm_password]):
                flash("Tous les champs sont obligatoires.", "danger")
                return redirect(url_for('register'))
                
            # Validation de l'email avec une expression régulière
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash("Format d'email invalide.", "danger")
                return redirect(url_for('register'))
                
            # Validation de la date
            try:
                date_naissance = datetime.strptime(date_naissance, '%Y-%m-%d').date()
                # Vérification que la date n'est pas dans le futur
                if date_naissance > datetime.now().date():
                    flash("La date de naissance ne peut pas être dans le futur.", "danger")
                    return redirect(url_for('register'))
            except ValueError:
                flash("Format de date invalide.", "danger")
                return redirect(url_for('register'))
                
            # Validation de la complexité du mot de passe
            if len(password) < 12:
                flash("Le mot de passe doit contenir au moins 12 caractères.", "danger")
                return redirect(url_for('register'))
                
            if not (any(c.isupper() for c in password) and 
                    any(c.islower() for c in password) and
                    any(c.isdigit() for c in password) and
                    any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password)):
                flash("Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial.", "danger")
                return redirect(url_for('register'))
                
            # Vérification de la correspondance des mots de passe
            if password != confirm_password:
                flash("Les mots de passe ne correspondent pas.", "danger")
                return redirect(url_for('register'))
                
            # Vérification que l'utilisateur n'existe pas déjà
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                # Message générique pour éviter la divulgation d'informations
                flash("Une erreur s'est produite lors de l'inscription.", "warning")
                # Ajout d'un délai pour prévenir les attaques par timing
                time.sleep(random.uniform(0.5, 1.5))
                return redirect(url_for('register'))
                
            # Hachage du mot de passe avec un algorithme robuste et salting automatique
            hashed_password = generate_password_hash(password)
            
            # Création de l'utilisateur avec limitation des entrées
            user = User(
                nom=nom[:50],  # Limiter la longueur
                prenom=prenom[:50],
                date_naissance=date_naissance,
                email=email[:100],
                password=hashed_password,
                #is_active=False,  # L'utilisateur doit être activé par email
                #created_at=datetime.now(),
                #last_login=None
            )
            
            # Traitement en base de données avec gestion d'erreur
            try:
                db.session.add(user)
                db.session.commit()
                
                
                # Message de succès
                flash("Votre compte a été créé. Veuillez vérifier votre email pour activer votre compte.", "success")

                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash("Une erreur s'est produite lors de l'inscription.", "danger")
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"[DEBUG] Erreur lors de l'inscription : {e}")  # à retirer en prod
            flash("Une erreur s'est produite. Veuillez réessayer.", "danger")
            return redirect(url_for('register'))
            
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    MAX_ATTEMPTS = 3
    TIME_WINDOW = timedelta(seconds=0.5)
    LOCK_DURATION = timedelta(minutes=5)
    
    # Initialisation des compteurs de session
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
    if 'last_attempt' not in session:
        session['last_attempt'] = str(datetime.now(timezone.utc))
    
    if request.method == 'POST':
        now = datetime.now(timezone.utc)
        email = request.form['email']
        password = request.form['password']
        
        # 1. Vérification du blocage de session
        """ lock_until = session.get('lock_until')
        if lock_until:
            lock_until_time = datetime.fromisoformat(lock_until)
            if now < lock_until_time:
                wait = int((lock_until_time - now).total_seconds() // 60) + 1
                flash(f"Trop de tentatives dans cette session. Réessayez dans {wait} minute(s).", "danger")
                return redirect(url_for('login'))
            else:
                session['login_attempts'] = 0
                session.pop('lock_until') """
        
        # 2. Vérification du délai entre les tentatives
        last_attempt_time = datetime.fromisoformat(session['last_attempt'])
        if now - last_attempt_time < TIME_WINDOW:
            flash("Veuillez attendre quelques secondes avant une nouvelle tentative.", "warning")
            return redirect(url_for('login'))
        session['last_attempt'] = str(now)
        
        # 3. Vérification du blocage utilisateur en base de données
        user = User.query.filter_by(email=email).first()
        if user:
            # Vérifier si l'utilisateur est bloqué
            locked_until = user.locked_until

            if user.is_locked and locked_until:
                # S'assurer que locked_until est aussi aware
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)

                if locked_until > now:
                    wait = int((locked_until - now).total_seconds() // 60) + 1
                    flash(f"Ce compte est temporairement bloqué. Réessayez dans {wait} minute(s).", "danger")
                    return redirect(url_for('login'))
            elif user.is_locked and user.locked_until and user.locked_until <= now:
                # Débloquer l'utilisateur si le temps est écoulé
                user.is_locked = False
                user.locked_until = None
                user.failed_login_attempts = 0
                db.session.commit()
        
        # 4. Vérification des identifiants
        if user and check_password_hash(user.password, password):
            # Réinitialiser le compteur de tentatives
            if hasattr(user, 'failed_login_attempts'):
                user.failed_login_attempts = 0
                user.is_locked = False
                user.locked_until = None
                db.session.commit()
            
            login_user(user)
            session['login_attempts'] = 0
            session.pop('lock_until', None)
            return redirect(url_for('dashboard'))
        elif user and not check_password_hash(user.password, password):
            # Incrémenter le compteur de session
            flash("Identifiants invalides.", "danger")
            if session['login_attempts']> MAX_ATTEMPTS:
                session['login_attempts']=0
            session['login_attempts'] += 1
            flash(f"Identifiants invalides. Tentative {session['login_attempts']} sur {MAX_ATTEMPTS}", "danger")
        else :
            flash("Cet utilisateur n'existe pas.", "danger")
            # Bloquer la session si trop de tentatives
            """ if session['login_attempts'] >= MAX_ATTEMPTS:
                session['lock_until'] = str(now + LOCK_DURATION)
                flash("Trop de tentatives. Cette session est temporairement bloquée.", "danger") """
            
            # Bloquer l'utilisateur si trop de tentatives (seulement si l'email existe)
        if user:
            if not hasattr(user, 'failed_login_attempts'):
                    # Si le champ n'existe pas dans le modèle, ignorer cette partie
                pass
            else:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= MAX_ATTEMPTS:
                    session['login_attempts'] = 0
                    flash("Trop de tentatives. Cette session est temporairement bloquée.", "danger")
                    user.is_locked = True
                    user.locked_until = now + LOCK_DURATION
                db.session.commit()
            
        """ flash(f"Identifiants invalides. Tentative {session['login_attempts']} sur {MAX_ATTEMPTS}", "danger") """
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    from models import Task  # pour éviter les imports circulaires
    user_groups = current_user.groups

    # Récupérer les tâches qui appartiennent à l'utilisateur OU aux groupes auxquels il appartient
    tasks = Task.query.filter(
        (Task.user_id == current_user.id) | (Task.group_id.in_([group.id for group in user_groups]))
    ).all()    
    return render_template('dashboard.html', tasks=tasks)

@app.route('/tasks/new', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        deadline_str = request.form['deadline']
        status = request.form['status']
        """ file = request.files['file'] """

        deadline_date = datetime.strptime(deadline_str, '%Y-%m-%d').date()
        
        user_id = current_user.id
        print(f'User ID: {user_id}')
        task = Task(title=title, description=description, priority=priority, deadline=deadline_date, status=status, user_id=user_id)
        db.session.add(task)
        db.session.commit()
        UPLOAD_FOLDER = '/var/www/html/uploads'
        os.makedirs(UPLOAD_FOLDER,exist_ok=True)
        # Traitement de l'upload du fichier (si présent)
        fichiers = request.files.getlist('files')
        if fichiers:
            for file in fichiers:
                # Lire le fichier en binaire
                if file and file.filename and file.filename.strip():
                    if allowed_file(file.filename):
                        random_name = generate_random_filename(file.filename)
                        path=os.path.join(UPLOAD_FOLDER,random_name)
                        file.save(path)
                        filedata = file.read()
                        # Créer une instance de File et l'associer à la tâche
                        new_file = File(
                            # filename=secure_filename(file.filename),
                            filename=file.filename,
                            task_id=task.id,
                            filedata=filedata
                        )

                        db.session.add(new_file)
                        db.session.commit()

        flash("Tâche créée avec succès.", "success")
        return redirect(url_for('dashboard'))
    return render_template('tasks_new.html')



@app.route('/groupe/<int:groupe_id>', methods=['GET'])
@login_required
def voir_groupe(groupe_id):
    from models import Group
    group = Group.query.get_or_404(groupe_id)
    if current_user not in group.members:
        abort(404)
    return render_template('voir_groupe.html', group=group)


@app.route('/rechercher_utilisateur')
def rechercher_utilisateur():
    from models import User
    prénom = request.args.get('prénom', '')
    if prénom:
        # Recherche les utilisateurs dont le prénom correspond
        users = User.query.filter(User.prenom.ilike(f'%{prénom}%')).all()
        # Renvoie les utilisateurs sous forme de JSON
        return jsonify([{'id': user.id, 'prenom': user.prenom, 'nom': user.nom} for user in users])
    return jsonify([])  # Retourne une liste vide si aucune recherche n'est effectuée



@app.route('/groupe/<int:groupe_id>/retirer_membre/<int:membre_id>', methods=['POST'])
@login_required
def retirer_membre(groupe_id, membre_id):
    from models import Group, User

    group = Group.query.get_or_404(groupe_id)
    membre = User.query.get_or_404(membre_id)

    # Vérifie que l'utilisateur courant est bien l'admin du groupe
    if group.admin_id != current_user.id:
        flash("Vous n'avez pas l'autorisation de modifier ce groupe.", "danger")
        return redirect(url_for('voir_groupe', groupe_id=groupe_id))

    # Ne pas permettre de retirer l'admin lui-même
    if membre.id == group.admin_id:
        flash("Vous ne pouvez pas vous retirer en tant qu'administrateur.", "warning")
        return redirect(url_for('voir_groupe', groupe_id=groupe_id))

    # Retirer le membre s'il est bien dans le groupe
    if membre in group.members:
        group.members.remove(membre)
        db.session.commit()
        flash(f"{membre.prenom} {membre.nom} a été retiré du groupe.", "success")
    else:
        flash("Ce membre ne fait pas partie du groupe.", "danger")

    return redirect(url_for('voir_groupe', groupe_id=groupe_id))



@app.route('/groupe/<int:groupe_id>/ajouter_membre', methods=["POST"])
@login_required
def ajouter_membre(groupe_id):
    from models import Group, User,Task
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()
    group = Group.query.get_or_404(groupe_id)
    tasks = Task.query.get_or_404(groupe_id).all()
    for task in tasks:
        new_task= Task(title=task.title,description=task.description,priority=task.priority,deadline=task.deadline,status=task.status,user_id=user.id)
        db.session.add(new_task)
        db.session.commit()

    if user and user not in group.members:
        group.members.append(user)
        db.session.commit()
        flash("Membre ajouté.")
        
    else:
        flash("Utilisateur introuvable ou déjà membre.")
    

    return redirect(url_for('voir_groupe', groupe_id=groupe_id))



@app.route("/groupe/<int:groupe_id>/ajouter_tache", methods=["POST"])
@login_required
def ajouter_tache(groupe_id):
    from models import Group, Task,File
    title = request.form["title"]
    description = request.form.get("description")
    priorite = request.form.get("priority")
    deadline = request.form.get("deadline")
    status = "En cours"
    group = Group.query.get_or_404(groupe_id)

    # pour chaque membre, créer une tâche individuelle
    for member in group.members:

        new_task = Task(
            title=title,
            description=description,
            priority=priorite,
            deadline=datetime.strptime(deadline, "%Y-%m-%d") if deadline else None,
            group_id=groupe_id,
            status=status,
            user_id=member.id, 
        )
        db.session.add(new_task)
        db.session.commit()

    task_files = request.files.getlist("files")
    for file in task_files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_data = file.read()
            uploaded_file = File(filename=filename, data=file_data, task_id=new_task.id)
            db.session.add(uploaded_file)

    db.session.commit()
    flash("Tâche ajoutée.")
    return redirect(url_for('voir_groupe', groupe_id=groupe_id))

@app.route("/groupe/<int:groupe_id>/modifier_tache/<int:task_id>", methods=["POST","GET"])
@login_required
def modifier_tache(groupe_id, task_id):


    tache = Task.query.get(task_id)
    # if tache.user_id != current_user.id:
    #     flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
    #     return redirect(url_for('voir_groupe', groupe_id=groupe_id))
    if tache.status == "Fait":
        flash('Cette tâche terminé', 'danger')
        return redirect(url_for('view_task', task_id=task_id))

    if request.method == 'POST':
        tache.title = request.form['title']
        tache.description = request.form['description']
        tache.priority = int(request.form['priority'])
        tache.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        tache.status = request.form['status']

        # Gérer la suppression de fichiers si des cases sont cochées
        files_to_delete = request.form.getlist('delete_files')
        for file_id in files_to_delete:
            file = File.query.get(int(file_id))
            if file and file.task_id == tache.id:
                db.session.delete(file)

        fichiers = request.files.getlist('files')
        
        for file in fichiers:
            # Lire le fichier en binaire
            if file and file.filename and file.filename.strip():
                filedata = file.read()

                # Créer une instance de File et l'associer à la tâche
                new_file = File(
                    # filename=secure_filename(file.filename),
                    filename=file.filename,
                    task_id=tache.id,
                    filedata=filedata
                )

                db.session.add(new_file)
            
        db.session.commit()
        
        flash('La tâche a été mise à jour avec succès!', 'success')
        return redirect(url_for('voir_groupe', groupe_id=groupe_id))
    return render_template('update.html', tache=tache)


    

@app.route("/groupe/<int:groupe_id>/supprimer_tache/<int:task_id>", methods=["POST","GET"])
@login_required
def supprimer_tache(groupe_id, task_id):
    from models import Group, Task,File
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash("Tâche supprimée.")
    return redirect(url_for('voir_groupe', groupe_id=groupe_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for('login'))

@app.route('/profil/edit', methods=['GET', 'POST'])
@login_required
def edit_profil():
    if request.method == 'POST':
        current_user.nom = request.form['nom']
        current_user.prenom = request.form['prenom']
        current_user.date_naissance = datetime.strptime(request.form['date_naissance'], '%Y-%m-%d').date()
        db.session.commit()
        flash("Profil mis à jour avec succès.", "success")
        return redirect(url_for('profil'))
    
    return render_template('edit_profil.html', user=current_user)

@app.route('/creer_groupe', methods=['GET', 'POST'])
@login_required
def creer_groupe():
    from models import User, Group, Task, File
    users = User.query.all()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        selected_members=request.form.getlist("members")
        print("VOICI LA LISTE DES MEMBRES", selected_members)
        if selected_members:
            selected_members = selected_members[0].split(',')
        try:
            selected_members = [int(user_id) for user_id in selected_members if user_id.isdigit()]
            print("Liste sélectionnée",selected_members)
        except ValueError:
            flash("Erreur dans la sélection des membres.", "danger")
            return redirect(url_for('creer_groupe'))

        # Création du groupe
        nouveau_groupe = Group(name=name, description=description, admin_id=current_user.id)
        if nouveau_groupe:
            print("YES")
        print(nouveau_groupe.name)
        print(nouveau_groupe.description)

        

        # Membres
        members_to_add = set(selected_members)  # Utilisez un ensemble pour éviter les doublons
        if current_user.id not in members_to_add:
            members_to_add.add(current_user.id)

        for user_id in members_to_add:
            user = User.query.get(user_id)
            if user and user not in nouveau_groupe.members:
                nouveau_groupe.members.append(user)
            
        print("Voici les nouveaux membres du groupe:",nouveau_groupe.members)
            
        db.session.add(nouveau_groupe)
        db.session.commit()

        # Création de tâche (si remplie)
        task_title = request.form.get('task_title')
        if task_title:
            task_description = request.form.get('task_description', '')
            task_priority = request.form.get('task_priority', 'moyenne')
            task_deadline_str = request.form.get('task_deadline')
            task_deadline = datetime.strptime(task_deadline_str, '%Y-%m-%d').date()

            task_files = request.files.getlist('task_files')

            task_status = "En cours"
            if task_deadline < datetime.today().date():
                task_status = "Pas fait"
    # pour chaque membre, créer une tâche individuelle
            for members_id in members_to_add :
                new_task = Task(
                    title=task_title,
                    description=task_description,
                    priority=task_priority,
                    deadline=task_deadline,
                    group_id=nouveau_groupe.id,
                    user_id=members_id,
                    status=task_status
                )
                db.session.add(new_task)
                db.session.commit()

            for file in task_files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    file_data = file.read()
                    uploaded_file = File(
                        filename=filename,
                        filedata=file_data,
                        task_id=new_task.id
                    )
                    db.session.add(uploaded_file)
                    db.session.commit()

        flash("Groupe (et tâche si ajoutée) créé avec succès", "success")
        return redirect(url_for('dashboard'))

    return render_template('creer_groupe.html', users=users)

@app.route('/profil/credentials', methods=['GET', 'POST'])
@login_required
def edit_credentials():
    from models import User
    if request.method == 'POST':
        email = request.form['email']
        if current_user.email == email :
            user =User.query.filter_by(email=email).first()
            old_password = request.form['old_password']
            if user and check_password_hash(user.password, old_password):
                password = request.form['password']
                confirm_password = request.form['confirm_password']

                if password != confirm_password:
                    flash("Les mots de passe ne correspondent pas.", "danger")
                    return redirect(url_for('edit_credentials'))

                existing_email = User.query.filter_by(email=email).first()
                if existing_email and existing_email.id != current_user.id:
                    flash("Cet email est déjà utilisé par un autre utilisateur.", "warning")
                    return redirect(url_for('edit_credentials'))

                current_user.email = email
                current_user.password = generate_password_hash(password)
                db.session.commit()
                flash("Identifiants mis à jour avec succès.", "success")
                return redirect(url_for('profil'))
            else :
                flash("Ancien mot de passe incorrect.", "danger")

    return render_template('edit_credentials.html', user=current_user)


@app.route('/profil')
@login_required
def profil():
    return render_template('profil.html', user=current_user)


@app.route('/tasks/<int:task_id>')
@login_required
def view_task(task_id):
    task = Task.query.get(task_id)
    if task.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        return redirect(url_for('dashboard'))
    #from models import Task  # pour éviter les imports circulaires
    #task = Task.query.get(task_id)
    return render_template('tache-detail.html', tache=task )

"""
@app.route('/task')
@login_required
def view_task():
    from models import db,Task
    task_id = request.args.get("id")
    # Utiliser des requêtes paramétrées (déjà présent dans votre code original)
    query = text("SELECT * FROM task WHERE id = :id")
    result = db.session.execute(query, {"id": task_id}).fetchone()
    files_query = text("SELECT * FROM file WHERE task_id = :id")
    files = db.session.execute(files_query, {"id": task_id}).fetchall()
    # ⚠️ Création volontaire d'une vulnérabilité SQLi pour des tests
    query = text(f"SELECT * FROM task WHERE id = {task_id}")  # Injection directe non sécurisée
    result = db.session.execute(query).fetchone()
    
    files_query = text(f"SELECT * FROM file WHERE task_id = {task_id}")  # Également vulnérable
    files = db.session.execute(files_query).fetchall()
    task = Task.query.get_or_404(task_id)

    if current_user.id != task.user_id and task.group_id not in [group.id for group in current_user.groups] :
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        abort(404)
        return redirect(url_for('dashboard'))

    return render_template('tache-detail.html', tache=result, files=files)
"""

@app.route('/files/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    task = Task.query.get(file.task_id)
    if task.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        return redirect(url_for('dashboard'))
    return send_file(io.BytesIO(file.filedata), download_name=file.filename,as_attachment=False )

@app.route('/update/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update(task_id):
    tache = Task.query.get(task_id)
    if tache.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        return redirect(url_for('dashboard'))
    if tache.status == "Fait":
        flash('Cette tâche terminé', 'danger')
        return redirect(url_for('view_task', task_id=task_id))

    if request.method == 'POST':
        tache.title = request.form['title']
        tache.description = request.form['description']
        tache.priority = int(request.form['priority'])
        tache.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        tache.status = request.form['status']

        # Gérer la suppression de fichiers si des cases sont cochées
        files_to_delete = request.form.getlist('delete_files')
        for file_id in files_to_delete:
            file = File.query.get(int(file_id))
            if file and file.task_id == tache.id:
                db.session.delete(file)

        fichiers = request.files.getlist('files')
        
        for file in fichiers:
            # Lire le fichier en binaire
            if file and file.filename and file.filename.strip():
                filedata = file.read()

                # Créer une instance de File et l'associer à la tâche
                new_file = File(
                    # filename=secure_filename(file.filename),
                    filename=file.filename,
                    task_id=tache.id,
                    filedata=filedata
                )

                db.session.add(new_file)
            
        db.session.commit()
        
        flash('La tâche a été mise à jour avec succès!', 'success')
        return render_template('tache-detail.html', tache=tache)
    return render_template('update.html', tache=tache)



@app.route('/groupe/<int:groupe_id>/supprimer', methods=["POST","DELETE","GET"])
@login_required
def supprimer_groupe(groupe_id):
    from models import Group
    groupe = Group.query.get_or_404(groupe_id)
    if groupe.admin_id != current_user.id:
        abort(403)  # interdit
    db.session.delete(groupe)
    db.session.commit()
    flash("Groupe supprimé avec succès.", "info")
    return redirect(url_for('dashboard'))



@app.route('/finished/<int:task_id>')
@login_required
def finished(task_id):
    tache = Task.query.get(task_id)
    if tache.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        return redirect(url_for('dashboard'))
    tache.status= "Fait"
    db.session.commit()
    return redirect(url_for('view_task', task_id=task_id))

@app.route('/supprimer_task/<int:task_id>', methods=['GET'] )
@login_required
def supprimer_task(task_id):
    tache = Task.query.get(task_id)
    
    if tache.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(tache)
    db.session.commit()

    return redirect(url_for('dashboard'))

# Route pour afficher le calendrier
@app.route('/calendar')
@login_required
def calendar():
    tasks = Task.get_tasks_for_user(current_user.id)
    events = [
        {
            'title': task.title,
            'start': task.deadline.strftime('%Y-%m-%d'),
            'description': task.description,
            'priority': task.priority,
            'status': task.status
        }
        for task in tasks
    ]
    return render_template('calendar.html', events=events)

with app.app_context():
    db.create_all()
   

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
