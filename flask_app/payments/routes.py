from flask import Blueprint, render_template, url_for, redirect, request, flash
from flask_login import current_user, login_required

from ..forms import SendPaymentForm, RequestPaymentForm
from ..models import User, Payment
from ..utils import current_time

import io
import base64

from datetime import datetime, timedelta

from mongoengine.queryset.visitor import Q

import pandas as pd
import matplotlib
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure

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

def create_plot(balances):
    xs = list([i for i in range(-7, 1)])
    fig = Figure()
    axis = fig.add_subplot(1, 1, 1)
    axis.plot(xs, list(balances)[1:])
    return fig

@payments.route("/analytics")
@login_required
def analytics():
    balances = [current_user.balance, current_user.balance]
    for i in range(0, 7):
        upper_bound = datetime.now() - timedelta(days=i)
        lower_bound = datetime.now() - timedelta(days=i+1)
        payments_in_range = Payment.objects(Q(payer=current_user._get_current_object()) & Q(date__lte=upper_bound) & (Q(date__gt=lower_bound)))
        receives_in_range = Payment.objects(Q(receiver=current_user._get_current_object()) & Q(date__lte=upper_bound) & (Q(date__gt=lower_bound)))
        balance = balances[i + 1]
        for payment in payments_in_range:
            balance -= payment.amount

        for receive in receives_in_range:
            balance += receive.amount

        balances[i + 1] = balance
        balances.append(balance)

    balances = reversed(balances)
    figure = create_plot(balances)
    output = io.BytesIO()
    FigureCanvas(figure).print_png(output)
    pngImageB64String = "data:image/png;base64,"
    pngImageB64String += base64.b64encode(output.getvalue()).decode('utf8')

    return render_template("analytics.html", figure=pngImageB64String)

    


def transaction_history(user):
    return render_template("history.html", username_form=username_form, user = user)
    
