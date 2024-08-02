from app import app, db, User

with app.app_context():

    User.query.delete()
    db.session.commit()
    print("All users have been deleted.")
