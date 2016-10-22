from flask import Flask
from codeLinc2016.model import db

class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = 'idontknowwhatthisis'
    SECURITY_PASSWORD_SALT = "fortoken"
    MAIL_DEFAULT_SENDER = "support@phoenixnow.org"
    MAIL_SERVER = os.environ.get('EMAILSERVER')
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.environ.get('EMAIL')
    MAIL_PASSWORD = os.environ.get('EMAILPASS')

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:password@db/postgres'

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///file.db'

app = Flask(__name__)
db = SQLAlchemy(app)

if os.environ.get('FLASK_DEBUG'):
    app.config.from_object(DevelopmentConfig)
else:
    app.config.from_object(ProductionConfig)

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/createdb')
def create_db():
    db.create_all()
    return 'DB created'
