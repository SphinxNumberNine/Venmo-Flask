from flask import Blueprint, render_template, url_for, redirect, request, flash
from flask_login import current_user

from ..forms import SendPaymentForm, RequestPaymentForm
from ..models import User, Payment
from ..utils import current_time

payments = Blueprint('payments', __name__)

@payments.route("/transaction_history/<friend>")
def send_payment(friend, amount):
    form = SendPaymentForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        form.validate_credits(form.credit.data)
        #next_balance = current_user.balance - amount
        #if next_balance < 0:
        #    return redirect(url_for("payments.transaction_history"))
        current_user.balance -= amount
        friend.balance += amount
        current_user.save()
        friend.save()
        return redirect(url_for("payments.transaction_history"))
    return render_template("account.html", title="Account", username_form=username_form)

@payments.route("/transaction_history/<friend>")
def request_payment(friend, amount):
    form = SendPaymentForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        return redirect(url_for("payments.transaction_history"))
    return render_template("account.html", title="Account", username_form=username_form)

def transaction_history(user):
    return render_template("history.html", username_form=username_form, user = user)
    
