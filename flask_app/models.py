from flask_login import UserMixin
from datetime import datetime
from . import db, login_manager
from . import config
import base64

@login_manager.user_loader
def load_user(user_id):
    return User.objects(username=user_id).first()

class User(db.Document, UserMixin):
    username = db.StringField(required=True, unique=True)
    email = db.EmailField(required=True, unique=True)
    firstname = db.StringField(required=True)
    lastname = db.StringField(required=True)
    password = db.StringField(required=True)
    balance = db.IntegerField(required=True)
    friends = db.ListField(db.ReferenceField(User))

    # Returns unique string identifying our object
    def get_id(self):
        return self.username

class Payment(db.Document):
    payer = db.ReferenceField(User, required=True)
    receiver = db.ReferenceField(User, required=True)
    comment = db.StringField(required=True, min_length=1, max_length=500)
    date = db.StringField(required=True)
    amount = db.IntegerField(required=True)
    
