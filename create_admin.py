from app import app, db, User
from werkzeug.security import generate_password_hash


def create_admin():
    admin_username = 'admin'
    admin_password = '123456pass'
    hashed_password = generate_password_hash(admin_password)
    admin = User(username=admin_username, password=hashed_password, is_admin=True)
    db.session.add(admin)
    db.session.commit()


with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        create_admin()
    print("Admin user created.")
