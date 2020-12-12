from flask import Blueprint, redirect, url_for, render_template, flash, request
from flask_login import current_user, login_required, login_user, logout_user

from .. import bcrypt
from ..forms import RegistrationForm, LoginForm, UpdateUsernameForm, UpdatePasswordForm, AddFriendForm
from ..models import User, Payment

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
        user.save()
        return redirect(url_for("users.login"))
    return render_template("register.html", title="Register", form=form)

@users.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("users.index"))
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
    form = SearchForm()
    if form.validate_on_submit():
        return redirect(url_for("users.account"))
    return render_template("index.html", form=form)

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
    return render_template("account.html", title="Account", username_form=username_form,)

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
