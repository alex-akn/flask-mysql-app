from flask import Flask, render_template, request, make_response, flash, redirect, url_for, session, logging, abort
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from http import HTTPStatus
import hashlib
import os
import base64
from datetime import datetime
from functools import wraps


app = Flask(__name__)

def authorization_required(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):        
        if 'logged_in' in session:
            return view_function(*args, **kwargs)
        else:
            flash('Authorization required', 'danger')
            return redirect(url_for('login'))
    return decorated_function

ENV = 'dev'

if ENV == 'dev':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flask:11235813@localhost/flask1'
else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = ''

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    username = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200))
    ragister_date = db.Column(db.TIMESTAMP(), default=datetime.utcnow)    

    DIGEST = 'sha384'
    ROUNDS = 100000

    def __init__(self, **document):
        self.name = document['name']
        self.username = document['username']
        self.email = document['email']
        #self.register_date = time.time()
        self.password = None
        super().__init__(**document)

    def set_password(self, password):
        salt = os.urandom(30)
        # Password-Based Key Derivation Function 2
        hash = hashlib.pbkdf2_hmac( 
            self.DIGEST, password.encode('utf-8'), salt, self.ROUNDS)
        self.password = '$'.join(
            [self.DIGEST,
            base64.urlsafe_b64encode(salt).decode('ascii'),
            base64.urlsafe_b64encode(hash).decode('ascii')
            ]
        )

    def check_password(self, password):
        digest, b64_salt, b64_expected_hash = self.password.split('$')
        salt = base64.urlsafe_b64decode(b64_salt)
        expected_hash = base64.urlsafe_b64decode(b64_expected_hash)
        computed_hash = hashlib.pbkdf2_hmac(
            digest, password.encode('utf-8'), salt, self.ROUNDS)
        return computed_hash == expected_hash


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text())
    created_date = db.Column(db.TIMESTAMP(), default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    user = db.relationship('User', backref=db.backref('articles', lazy=True))

# db.create_all()   # creates tables from models

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
def articles():
    articles = Article.query.all()
    return render_template('articles.html', articles=articles)

@app.route('/articles/<id>/')
def article(id):    
    try:
        id = int(id)
    except Exception as ex:
        print(ex)
        return make_response('Not found', HTTPStatus.NOT_FOUND)
    article = Article.query.filter_by(id=id).first()
    if not article:
        return make_response('Not found', HTTPStatus.NOT_FOUND)
    return render_template('article.html', article=article)



class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    username = StringField('Username', [validators.Length(min=4, max=200)])
    email = StringField('Email', [validators.Regexp(r"^[a-z0-9_-]+@[a-z0-9_-]+\.[a-z]{2,10}$", message="Invalid Email")])
    password = PasswordField('Password', [validators.DataRequired()])
    confirm = PasswordField('Confirm Password', [validators.EqualTo('password', message="Passwords do not match")])


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = form.password.data
        new_user = User(name = name, email=email, username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("You are now registered and can log in", 'success')
        return redirect(url_for('login'))
        # return make_response('OK', HTTPStatus.CREATED)

    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        #password_candidate = request.form['password']
        user = User.query.filter_by(username=username).first()
        print(user)
        if user and user.check_password(request.form['password']):
            #login_user(user)
            session['logged_in'] = True
            session['username'] = username
            app.logger.info('%s logged in successfully', user.username)
            return redirect(url_for('dashboard'))           
        else:
            app.logger.info('%s failed to log in', username)
            return render_template('login.html', error='Username or password is incorrect')
    return render_template('login.html')
    

@app.route('/dashboard', methods=['GET'])
@authorization_required
def dashboard():
    # show dashboard
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.clear()
        flash("Something bad might have happen", 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', articles = user.articles)


@app.route('/logout', methods=['GET'])
@authorization_required
def logout():
    session.clear()
    return redirect(url_for('login'))



class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])
    

@app.route('/add_article', methods=['GET', "POST"])
@authorization_required
def submit():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        user = User.query.filter_by(username=session['username']).first()
        arcticle = Article(title = title, body=body, user=user)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('article', id=str(arcticle.id)))

    return render_template('add_article.html', form=form, endpoint="/add_article")


@app.route('/edit_article/<id>', methods=['GET', "POST"])
@authorization_required
def edit_article(id):
    form = ArticleForm(request.form)
    try:
        id = int(id)
    except Exception as ex:
        print(ex)
        return make_response('Not found', HTTPStatus.BAD_REQUEST)    
    #return render_template('article.html', article=article)
    if request.method == 'POST':
        if form.validate():
            article = Article.query.filter_by(id=id).update(dict(title=form.title.data, body=form.body.data))
            db.session.commit()            
            
            return redirect(url_for('article', id=str(id)))
        else:
            app.logger.info("Failed attempt to update")
            return render_template('add_article.html', form=form, endpoint="/edit_article/{id}".format(id=id))

    article = Article.query.filter_by(id=id).first()
    if not article:
        return make_response('Not found', HTTPStatus.NOT_FOUND)

    form.title.data = article.title
    form.body.data = article.body
    endpoint="/edit_article/{id}".format(id=id)
    return render_template('add_article.html', form=form, endpoint=endpoint)


@app.route('/delete_article/<id>', methods=["POST"])
@authorization_required
def delete_article(id):    
    try:
        id = int(id)
    except Exception as ex:
        print(ex)
        return make_response('Not found', HTTPStatus.BAD_REQUEST)    
    #return render_template('article.html', article=article)
    if request.method == 'POST':
        article = Article.query.filter_by(id=id).delete()
        print(article)
        if not article:
            return make_response("Not found", HTTPStatus.NOT_FOUND)
        db.session.commit()
        app.logger.info("Article deleted")
        flash("Article Deleted", 'success')
    return redirect(url_for('dashboard'))     



if __name__ == '__main__':
    app.secret_key = "seekrit"
    app.run(use_reloader=True)