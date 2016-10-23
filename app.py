from flask import Flask, render_template, flash, url_for, redirect, request
import datetime
import bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.associationproxy import association_proxy
import os

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
app.secret_key = "this is the most secret key you'll ever see"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)

#ops = db.Table('ops',
#    db.Column('opportunity', db.Integer, db.ForeignKey('opportunity.id')),
#    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
#)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(500))
    lastname = db.Column(db.String(500))
    email = db.Column(db.String(120), unique=True)
    pw_hash = db.Column(db.String(500))
    opportunities = association_proxy("userops", "opportunity",
                    creator=lambda userops: UserOpportunity(opportunity=userops))

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
    date = db.Column(db.DateTime)
    time = db.Column(db.String(50))
    location = db.Column(db.String(100))
    users = association_proxy("userops", "user",
                    creator=lambda userops: UserOpportunity(user=userops))

    def __init__(self, name, description, hours, date, time, location, badge_name, badge_image):
        self.name = name
        self.description = description
        self.hours = hours
        self.date = datetime.datetime.strptime(date, "%Y-%m-%d").date()
        self.time = time
        self.location = location
        self.badge_name = badge_name
        self.badge_image = badge_image

    def __repr__(self):
        return '<Opportunity %r>' % self.name

class UserOpportunity(db.Model):
    __tablename__ = 'user_opportunity'

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    opportunity_id = db.Column(db.Integer, db.ForeignKey('opportunity.id'), primary_key=True)
    verified = db.Column(db.Boolean)

    opportunity = db.relationship(Opportunity, backref=db.backref("userops", cascade="all, delete, delete-orphan"))
    user = db.relationship(User, backref=db.backref("userops", cascade="all, delete, delete-orphan"))

    def __init__(self, user=None, opportunity=None, verified=False):
        self.user = user
        self.opportunity = opportunity
        self.verified = verified

class Verified(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    opportunity_id = db.Column(db.Integer)
    verified = db.Column(db.Boolean)

    def __init__(self, user_id, opportunity_id):
        self.user_id = user_id
        self.opportunity_id = opportunity_id

class Opportunity2():
    badge_name = ""
    badge_image = ""

    def __init__(self, badge_name, badge_image):
        self.badge_name = badge_name
        self.badge_image = badge_image

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
    user = current_user
    if user.is_authenticated:
        badges_opportunity = []
        hours = 0
        for userop in user.userops:
            if userop.verified:
                badges_opportunity.append(userop.opportunity)
                hours += userop.opportunity.hours

        badges = badges_opportunity[:]
        
        if hours > 10:
            badges.append(Opportunity2("10 Hours!", "no link"))
        if hours > 20:
            badges.append(Opportunity2("20 Hours!", "no link"))

        opportunities = Opportunity.query.all()

        score = 5 * len(badges_opportunity) + 10 * hours + 20 * len(badges)
        return render_template("LoggedInHome.html", score=score, badges_opportunity=badges_opportunity, hours=hours, badges=badges, opportunities=opportunities)
    return render_template("NotLoggedInHome2.html") 

@app.route('/verify/<int:user_id>/<int:opp_id>')
@login_required
def verify(user_id, opp_id):
    user = current_user
    if user.is_admin():
        opportunity = Opportunity.query.filter_by(id=opp_id).first()
        user2 = User.query.filter_by(id=user_id).first()
        for userop in user2.userops:
            if userop.opportunity == opportunity:
                userop.verified = True
        db.session.commit()
        return redirect(url_for("admin"))

@app.route('/complete/<int:opp_id>')
def complete(opp_id):
    user = current_user
    opportunity = Opportunity.query.filter_by(id=opp_id).first()
    dontadd = False
    for opportunityone in user.opportunities:
        if opportunityone == opportunity:
            dontadd = True
            user.opportunities.remove(opportunity)
    if dontadd == False:
        user.opportunities.append(opportunity)
    db.session.commit()
    return redirect(url_for("home"))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = current_user

    users = User.query.all()
    opportunities = Opportunity.query.all()
    today = datetime.date.today()

    if user.is_admin():
        if request.method == 'POST':
            r = request.form
            opportunity = Opportunity(r['name2'], r['description'],
                    int(r['hours']), r['date'], r['time'], r['location'], r['badgename'], r['badgeimage'])
            db.session.add(opportunity)
            db.session.commit()
            flash("Opportunity added.")
            return redirect(url_for("admin"))
        else:
            return render_template("admin.html", today=today, users=users, opportunities=opportunities)
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
