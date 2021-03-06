from flask_login import UserMixin
from datetime import datetime
from . import db, login_manager
from . import config
from .utils import current_time
import base64
import pyotp

@login_manager.user_loader
def load_user(user_id):
    return User.objects(username=user_id).first()

class User(db.Document, UserMixin):
    username = db.StringField(required=True, unique=True)
    email = db.EmailField(required=True, unique=True)
    firstname = db.StringField(required=True)
    lastname = db.StringField(required=True)
    password = db.StringField(required=True)
    balance = db.FloatField(required=True, min_value=0.0, max_value=10000.0)
    friends = db.ListField(db.ReferenceField('self'))
    otp_secret = db.StringField(required=True, min_length=16,
                                max_length=16, default=pyotp.random_base32())

    # Returns unique string identifying our object
    def get_id(self):
        return self.username

class Payment(db.Document):
    payer = db.ReferenceField('User', required=True)
    receiver = db.ReferenceField('User', required=True)
    accepted = db.BooleanField(required=True, default=False)
    comment = db.StringField(required=True, min_length=1, max_length=500)
    date = db.DateTimeField(required=True)
    amount = db.FloatField(required=True, min_value=0.01, max_value=10000.0)
    completed = db.BooleanField(required=True, default=False)
    
