from extensions import db
from flask_login import UserMixin


# Table d'association pour les membres du groupe
group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100))
    prenom = db.Column(db.String(100))
    date_naissance = db.Column(db.Date)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    is_locked = db.Column(db.Boolean)  # Correction de "booleen" à "Boolean"
    locked_until = db.Column(db.DateTime)  # Changé à DateTime pour inclure l'heure
    tasks = db.relationship('Task', backref='user', lazy=True)
    groups = db.relationship('Group', secondary=group_members, back_populates='members')

    def __repr__(self):
        return f'<User {self.email}>'


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # nullable=True car peut être une tâche de groupe
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)

    title = db.Column(db.String(100))
    description = db.Column(db.String(2500))
    priority = db.Column(db.Integer, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(100), nullable=False)

    # Relation avec les fichiers
    files = db.relationship('File', backref='task', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Task {self.title}>'
    
    @staticmethod
    def get_tasks_for_user(user_id):
        return Task.query.filter_by(user_id=user_id).all()
    
    def get_user_full_name(self):
        if self.user:
            return f"{self.user.prenom} {self.user.nom}"
        return "Utilisateur inconnu"


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    filedata = db.Column(db.LargeBinary, nullable=False)  # Colonne pour stocker le fichier en binaire


    def __repr__(self):
        return f'<File {self.filename}>'


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(2500))
    admin = db.relationship('User', backref='admin_groups', foreign_keys=[admin_id])
    members = db.relationship('User', secondary=group_members, back_populates='groups')
    tasks = db.relationship('Task', backref='group', lazy=True)

    def __repr__(self):
        return f'<Group {self.name}>'
