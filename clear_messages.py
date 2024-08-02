from app import app, db, Message

with app.app_context():

    db.session.query(Message).delete()
    db.session.commit()
    print("All messages have been deleted.")
