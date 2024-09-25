from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, EmailField, SelectField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from config import Config
from flask_login import login_user, LoginManager, logout_user, current_user, login_required, UserMixin
from datetime import datetime, timezone
from flask_restful import Api, Resource

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

bootstrap = Bootstrap(app)
api = Api(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=True)
    password = db.Column(db.String(150), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'admin'
    threads = db.relationship('Thread', backref='author', lazy=True)
    replies = db.relationship('Reply', backref='author', lazy=True)

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    replies = db.relationship('Reply', backref='thread', lazy=True, cascade="all, delete")

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Others', 'Others')])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number')
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=20),
        Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,20}$',
               message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.")
    ])
    confirmpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ThreadForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Create Thread')

class ReplyForm(FlaskForm):
    body = TextAreaField('Reply', validators=[DataRequired()])
    submit = SubmitField('Add Reply')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
def home():
    threads = Thread.query.all()
    return render_template('Home.html', threads=threads)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user, remember=False)
            if user.role == 'user':
                return redirect(url_for('user'))
            elif user.role == 'admin':
                return redirect(url_for('admin'))
        else:
            flash("Incorrect credentials")
    return render_template('Login.html', form=form)

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            email=form.email.data,
            password=form.password.data,
            phone=form.phone.data,
            gender=form.gender.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Data received')
        return redirect(url_for('login'))
    return render_template('Register.html', form=form)

@app.route('/user')
@login_required
def user():
    threads1 = Thread.query.filter_by(user_id=current_user.id).all()
    threads2 = Thread.query.filter(Thread.user_id != current_user.id).all()
    return render_template('User.html', threads1=threads1, threads2=threads2)

@app.route('/admin')
@login_required
def admin():
    threads = Thread.query.all()
    return render_template('Admin.html', threads=threads)

@app.route('/thread/new', methods=['GET', 'POST'])
@login_required
def new_thread():
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data, body=form.body.data, user_id=current_user.id)
        db.session.add(thread)
        db.session.commit()
        if current_user.role == 'user':
            return redirect(url_for('user'))
        else:
            return redirect(url_for('admin'))
    return render_template('AddThread.html', form=form)

@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
@login_required
def view_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    replies = Reply.query.filter_by(thread_id=thread.id).all()
    form = ReplyForm()
    
    if form.validate_on_submit():
        reply = Reply(body=form.body.data, user_id=current_user.id, thread_id=thread.id)
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('view_thread', thread_id=thread.id))

    return render_template('ViewThread.html', thread=thread, replies=replies, form=form)

@app.route('/thread/delete/<int:thread_id>', methods=['POST'])
@login_required
def delete_thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    if current_user.role != 'admin' and thread.author != current_user:
        flash('You do not have permission to delete this thread.')
        return redirect(url_for('home'))
    db.session.delete(thread)
    db.session.commit()
    flash('Thread deleted successfully.')
    if current_user.role == 'user':
        return redirect(url_for('user'))
    else:
        return redirect(url_for('admin'))

@app.route('/reply/delete/<int:reply_id>', methods=['POST'])
@login_required
def delete_reply(reply_id):
    reply = Reply.query.get_or_404(reply_id)
    if current_user.role != 'admin':
        flash('You do not have permission to delete this comment.')
        return redirect(url_for('view_thread', thread_id=reply.thread_id))
    
    db.session.delete(reply)
    db.session.commit()
    flash('Comment deleted successfully.')
    return redirect(url_for('view_thread', thread_id=reply.thread_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# REST API
class UserResource(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if user:
            return {
                "id": user.id,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "email": user.email
            }, 200
        return {"message": "User not found"}, 404

class UserListResource(Resource):
    def get(self):
        users = User.query.all()
        return [{
            "id": user.id,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "email": user.email
        } for user in users], 200

class ThreadResource(Resource):
    def get(self, thread_id):
        thread = Thread.query.get(thread_id)
        if thread:
            return {
                "id": thread.id,
                "title": thread.title,
                "body": thread.body,
                "date_posted": thread.date_posted.isoformat(),
                "author_id": thread.user_id
            }, 200
        return {"message": "Thread not found"}, 404

    def delete(self, thread_id):
        thread = Thread.query.get(thread_id)
        if thread:
            db.session.delete(thread)
            db.session.commit()
            return {"message": "Thread deleted"}, 200
        return {"message": "Thread not found"}, 404

class ThreadListResource(Resource):
    def get(self):
        threads = Thread.query.all()
        return [{
            "id": thread.id,
            "title": thread.title,
            "body": thread.body,
            "date_posted": thread.date_posted.isoformat(),
            "author_id": thread.user_id
        } for thread in threads], 200

    def post(self):
        data = request.get_json()
        new_thread = Thread(
            title=data['title'],
            body=data['body'],
            user_id=data['user_id']
        )
        db.session.add(new_thread)
        db.session.commit()
        return {"message": "Thread created", "id": new_thread.id}, 201

api.add_resource(UserListResource, '/api/users')
api.add_resource(UserResource, '/api/users/<int:user_id>')
api.add_resource(ThreadListResource, '/api/threads')
api.add_resource(ThreadResource, '/api/threads/<int:thread_id>')

if __name__ == '__main__':
    app.run(debug=True)
