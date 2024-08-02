import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, instance_relative_config=True)

DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(app.instance_path, 'messages.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_generated_secret_key_here'

os.makedirs(app.instance_path, exist_ok=True)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    likes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('user_likes', lazy=True))
    message = db.relationship('Message', backref=db.backref('message_likes', lazy=True))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        else:
            return "Invalid username or password"
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/')
def index():
    messages = Message.query.all()
    return render_template('index.html', messages=messages)


@app.route('/add', methods=['POST'])
def add_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    if content:
        user_id = session['user_id']
        new_message = Message(content=content, user_id=user_id)
        db.session.add(new_message)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/edit/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = Message.query.get(message_id)
    if message and message.user_id == session['user_id']:
        message.content = request.form['content']
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = Message.query.get(message_id)
    user = User.query.get(session['user_id'])
    if message and (message.user_id == session['user_id'] or user.is_admin):
        Like.query.filter_by(message_id=message_id).delete()
        db.session.delete(message)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/like/<int:message_id>', methods=['POST'])
def like_message(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    like = Like.query.filter_by(user_id=user_id, message_id=message_id).first()
    if like:
        return jsonify({'error': 'You have already liked this message'}), 400
    message = Message.query.get(message_id)
    if message:
        message.likes += 1
        new_like = Like(user_id=user_id, message_id=message_id)
        db.session.add(new_like)
        db.session.commit()
        return jsonify({'likes': message.likes})
    return jsonify({'error': 'Message not found'}), 404


@app.route('/clear', methods=['POST'])
def clear_messages():
    if 'user_id' not in session or not session.get('is_admin', False):
        return redirect(url_for('index'))
    db.session.query(Message).delete()
    db.session.commit()
    return redirect(url_for('index'))


def create_admin():
    admin_username = 'admin'
    admin_password = '123456'
    hashed_password = generate_password_hash(admin_password)
    admin = User(username=admin_username, password=hashed_password, is_admin=True)
    db.session.add(admin)
    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            create_admin()
    app.run(debug=True)
