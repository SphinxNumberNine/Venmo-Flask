from flask import Blueprint, redirect, url_for, render_template, flash, request, session
from flask_login import current_user, login_required, login_user, logout_user

from .. import bcrypt
from ..forms import RegistrationForm, LoginForm, UpdateUsernameForm, UpdatePasswordForm, AddFriendForm, AddCreditsForm
from ..models import User, Payment

import qrcode
import qrcode.image.svg as svg
from io import BytesIO
import pyotp

users = Blueprint('users', __name__)

@users.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("users.index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        
        hashed = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(username=form.username.data, email=form.email.data, password=hashed,
                    firstname=form.first_name.data, lastname=form.last_name.data, balance=form.balance.data)
        session['new_username'] = user.username
        user.save()
        return redirect(url_for("users.tfa"))
    return render_template("register.html", title="Register", form=form)

@users.route("/tfa")
def tfa():
    if 'new_username' not in session:
        return redirect(url_for('users.index'))

    headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0' # Expire immediately, so browser has to reverify everytime
    }

    return render_template('tfa.html'), headers

@users.route("/qr_code")
def qr_code():
    if 'new_username' not in session:
        return redirect(url_for('users.index'))
    
    user = User.objects(username=session['new_username']).first()
    session.pop('new_username')

    uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name='CMSC388J-2FA')
    img = qrcode.make(uri, image_factory=svg.SvgPathImage)
    stream = BytesIO()
    img.save(stream)

    headers = {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0' # Expire immediately, so browser has to reverify everytime
    }

    return stream.getvalue(), headers


@users.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("users.account"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects(username=form.username.data).first()
        if user is not None and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("users.account"))
        else:
            flash("Login failed. Check your username and/or password")
            return redirect(url_for("users.login"))
    return render_template("login.html", title="Login", form=form)

@users.route("/", methods=["GET", "POST"])
@login_required
def index():
    # form = SearchForm()
    # if form.validate_on_submit():
        # return redirect(url_for("users.account"))
    # return render_template("index.html", form=form)
    return "Venmo Clone"

@users.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("users.index"))

@users.route("/account", methods=["GET", "POST"])
@login_required
def account():
    username_form = UpdateUsernameForm()
    if username_form.validate_on_submit():
        current_user.modify(username=username_form.username.data)
        current_user.save()
        return redirect(url_for("users.account"))
    password_form = UpdatePasswordForm()
    if password_form.validate_on_submit():
        current_user.modify(password=password_form.password.data)
        current_user.save()
        return redirect(url_for("users.account"))
    add_credits_form = AddCreditsForm()
    if add_credits_form.validate_on_submit():
        new_balance = current_user.balance + add_credits_form.credit.data
        current_user.modify(balance=new_balance)
    return render_template("account.html", title="Account", username_form=username_form, password_form=password_form, add_credits_form=add_credits_form)

@users.route("/search-user/<name>", methods=["GET"])
@login_required
def user_search(name):
    #try:
    #Query database to find friend
    results = db.getCollection("users")
    #except ValueError as e:
    #    flash(str(e))
    #    return redirect(url_for("payments.transaction_history"))
    return render_template("query.html", results=results)

@users.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    add_friend_form = AddFriendForm()
    if add_friend_form.validate_on_submit():
        friend = User.objects(username=add_friend_form.username.data).first()
        existing_friends = current_user.friends
        if friend in existing_friends:
            return redirect(url_for('users.friends'))
        existing_friends.append(friend)
        current_user.modify(friends=existing_friends)
        return redirect(url_for('users.friends'))
    friends = []
    for friend in current_user.friends:
        friends.append((friend.firstname, friend.lastname, friend.username))
    return render_template("friends.html", friends=friends, add_friend_form=add_friend_form)
