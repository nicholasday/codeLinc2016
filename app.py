from flask import Flask, render_template, flash, url_for, redirect, request
from datetime import datetime
import bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
app.secret_key = "this is the most secret key you'll ever see"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)

ops = db.Table('ops',
    db.Column('opportunity', db.Integer, db.ForeignKey('opportunity.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(500))
    lastname = db.Column(db.String(500))
    email = db.Column(db.String(120), unique=True)
    pw_hash = db.Column(db.String(500))

    def __init__(self, firstname, lastname, email, password):
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def __repr__(self):
        return '<User %r>' % self.email

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        try:
            return unicode(self.id)  # python 2
        except NameError:
            return str(self.id)  # python 3

    def is_authenticated(self):
        """Return True if the user is verified."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.pw_hash.encode('utf-8'))

    def is_admin(self):
        if self.email in ['nick@nickendo.com']:
          return True
        else:
          return False

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.Integer)
    badge_name = db.Column(db.String(100))
    badge_image = db.Column(db.String(200))
    name = db.Column(db.String(100))
    description = db.Column(db.String(1000))
    date = db.Column(db.String(1000))

    def __init__(self, name, description, hours, date, badge_name, badge_image):
        self.name = name
        self.description = description
        self.hours = hours
        self.date = date
        self.badge_name = badge_name
        self.badge_image = badge_image

    def __repr__(self):
        return '<Opportunity %r>' % self.name

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

@app.route('/createdb')
def create_db():
    db.create_all()
    return 'DB created'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email = request.form['email']).first()

        if user.check_password(request.form['password']):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for("home"))
        else:
            flash('Wrong email or password.')
            return redirect(url_for("login"))
    else:
        return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        r = request.form
        user = User(r['firstname'], r['lastname'], r['email'], r['password'])
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Registered successfully.')
        return redirect(url_for("home"))
    else:
        return render_template("register.html")

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template("home.html")

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = current_user

    users = User.query.all()
    opportunities = Opportunity.query.all()

    if user.is_admin():
        if request.method == 'POST':
            r = request.form
            opportunity = Opportunity(r['name2'], r['description'], int(r['hours']), r['date'], r['badgename'], r['badgeimage'])
            db.session.add(opportunity)
            db.session.commit()
            flash("Opportunity added.")
            return redirect(url_for("admin"))
        else:
            return render_template("admin.html", users=users, opportunities=opportunities)
    else:
        flash("You are not an admin.")
        return redirect(url_for("home"))

@app.route('/admin/delete/<int:opp_id>')
def delete(opp_id):
    user = current_user

    if user.is_admin():
        opportunity = Opportunity.query.filter_by(id=opp_id).first()
        db.session.delete(opportunity)
        db.session.commit()
        return redirect(url_for("admin"))
    else:
        flash("You are not an admin.")
        return redirect(url_for("home"))
