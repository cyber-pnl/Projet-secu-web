from flask import Flask, render_template, redirect, url_for, flash, request, send_file,jsonify,abort
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os , io
from models import db, Task, User, File 
from werkzeug.utils import secure_filename
from sqlalchemy import text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app) 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

""" app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER']) """

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
    from models import User

    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        date_naissance = request.form['date_naissance']
        date_naissance = datetime.strptime(date_naissance, '%Y-%m-%d').date()
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Cet email est déjà utilisé.", "warning")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user = User(nom=nom, prenom=prenom, date_naissance=date_naissance, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Compte créé avec succès !", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Identifiants invalides.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    from models import Task  # pour éviter les imports circulaires
    tasks = Task.query.filter_by(user_id=current_user.id).all()
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
        
        # Supposons que vous avez une instance de l'utilisateur
        user = User.query.filter_by(email='utilisateur@example.com').first()

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
                    path=os.path.join(UPLOAD_FOLDER,file.filename)
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
    from models import Group, User
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()
    group = Group.query.get_or_404(groupe_id)

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
    # from models import Group, Task,File
    # task = Task.query.get_or_404(task_id)
    # task.title = request.form.get("title")
    # task.description = request.form.get("description")
    # task.priorite = request.form.get("priority")
    # deadline = request.form.get("deadline")
    # task.deadline = datetime.strptime(deadline, "%Y-%m-%d") if deadline else None

    # db.session.commit()
    # flash("Tâche mise à jour.")

    tache = Task.query.get(task_id)
    # if tache.user_id != current_user.id:
    #     flash('Vous n\'êtes pas autorisé à modifier cette tâche', 'danger')
    #     return redirect(url_for('voir_groupe', groupe_id=groupe_id))
    if tache.status == "Fait":
        flash('Cette tâche terminé', 'danger')
        return redirect(url_for('view_task', id=task_id))

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
        selected_members = request.form.getlist('members')
        print("VOICI LA LISTE DES MEMBRES", selected_members)
        if selected_members:
            selected_members = selected_members[0].split(',')
        try:
            selected_members = [int(user_id) for user_id in selected_members if user_id.isdigit()]
        except ValueError:
            flash("Erreur dans la sélection des membres.", "danger")
            return redirect(url_for('creer_groupe'))

        # Création du groupe
        nouveau_groupe = Group(name=name, description=description, admin_id=current_user.id)
        if nouveau_groupe:
            print("YES")
        print(nouveau_groupe.name)
        print(nouveau_groupe.description)

        db.session.add(nouveau_groupe)
        db.session.flush()

        # Membres
        members_to_add = set(selected_members)  # Utilisez un ensemble pour éviter les doublons
        if current_user.id not in members_to_add:
            members_to_add.add(current_user.id)

        for user_id in members_to_add:
            user = User.query.get(user_id)
            if user and user not in nouveau_groupe.members:
                nouveau_groupe.members.append(user)

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
                db.session.flush()

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

    return render_template('edit_credentials.html', user=current_user)


@app.route('/profil')
@login_required
def profil():
    return render_template('profil.html', user=current_user)

"""
@app.route('/tasks/<int:task_id>')
@login_required
def view_task(task_id):
    from models import Task  # pour éviter les imports circulaires
    task = Task.query.get(task_id)
    return render_template('tache-detail.html', tache=task )"""


@app.route('/task')
@login_required
def view_task():
    from models import db
    task_id = request.args.get("id")
    # ⚠️ Création volontaire d'une vulnérabilité SQLi pour des tests
    query = text(f"SELECT * FROM task WHERE id = {task_id}")  # Injection directe non sécurisée
    result = db.session.execute(query).fetchone()
    
    files_query = text(f"SELECT * FROM file WHERE task_id = {task_id}")  # Également vulnérable
    files = db.session.execute(files_query).fetchall()
    
    return render_template('tache-detail.html', tache=result, files=files)


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
        return redirect(url_for('view_task', id=task_id))

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
    tache.status= "Fait"
    db.session.commit()
    return redirect(url_for('view_task', id=task_id))

@app.route('/supprimer_task/<int:task_id>', methods=['GET'] )
@login_required
def supprimer_task(task_id):
    tache = Task.query.get(task_id)
    db.session.delete(tache)
    db.session.commit()

    return redirect(url_for('dashboard'))

# Route pour afficher le calendrier
@app.route('/calendar')
@login_required  # Assurez-vous que l'utilisateur est connecté avant d'afficher la page
def calendar():
    from models import Task
    # Récupérer toutes les tâches dont la date limite est dans le futur
    tasks = Task.query.filter(Task.deadline >= datetime.now().date()).all()
    
    # Créer une liste d'événements pour FullCalendar
    events = []
    for task in tasks:
        event = {
            'title': task.title,
            'start': task.deadline.isoformat(),  # Assurer que la date soit au format ISO
            'description': task.description
        }
        events.append(event)
    return render_template('calendar.html', events=events)

with app.app_context():
    db.create_all()
   

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
