#!/usr/bin/env python3
""" A small donation service so that users can request ln invoices

This plugin spins up a small flask server that provides a form to 
users who wish to donate some money to the owner of the lightning
node. The server can run on an arbitrary port and returns an invoice. 
Also a list of previously paid invoices (only those that used this
service) will be displayed. Displaying paid invoices could be made
optionally in a future version. 

Author: Rene Pickhardt (https://ln.rene-pickhardt.de)

you can see a demo of the plugin (and leave a tip) directly at:
       https://ln.rene-pickhardt.de/donation

LICENSE: MIT / APACHE
"""
import base64
import json
import multiprocessing
import qrcode
import sys


from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from io import BytesIO
from lightning.lightning import LightningRpc
from os.path import join
from random import random
from time import time
from wtforms import StringField,  SubmitField, IntegerField
from wtforms.validators import Required, NumberRange

# "FIXME: for debugging without plugin
rpc_interface = LightningRpc("/tmp/spark-env/ln1/lightning-rpc")


class DonationForm(FlaskForm):
    """Form for donations """
    amount = IntegerField("Enter how many Satoshis you want to donate!",
                          validators=[Required(), NumberRange(min=1, max=16666666)])
    description = StringField("Leave a comment (displayed publically)")
    submit = SubmitField('Donate')


def make_base64_qr_code(bolt11):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=4,
        border=4,
    )

    qr.add_data(bolt11)
    qr.make(fit=True)
    img = qr.make_image()

    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str


def ajax(label):
    msg = rpc_interface.listinvoices(label)["invoices"][0]
    if msg["status"] == "paid":
        return "Your donation has been received and is well appricated."
    return "waiting"


def donation_form():
    form = DonationForm()
    b11 = None
    qr = None
    label = None
    if form.validate_on_submit():
        amount = form.amount.data
        description = form.description.data
        label = "ln-plugin-donation-{}".format(random())
        invoice = rpc_interface.invoice(
            int(amount)*1000, label, description)
        b11 = invoice["bolt11"]
        qr = make_base64_qr_code(b11)

    invoices = rpc_interface.listinvoices()["invoices"]
    donations = []
    for invoice in invoices:
        if invoice["label"].startswith("ln-plugin-donation-"):
            # FIXME: change to paid after debugging
            if invoice["status"] == "paid":
                bolt11 = rpc_interface.decodepay(invoice["bolt11"])
                satoshis = int(bolt11["msatoshi"])//1000
                description = bolt11["description"]
                ts = bolt11["created_at"]
                donations.append((ts, satoshis, description))

    if b11 is not None:
        return render_template("donation.html", donations=sorted(donations, reverse=True), form=form, bolt11=b11, qr=qr, label=label)
    else:
        return render_template("donation.html", donations=sorted(donations, reverse=True), form=form)


def worker(port):
    app = Flask(__name__)
    # FIXME: use hexlified hsm secret or something else
    app.config['SECRET_KEY'] = 'you-will-never-guess-this'
    app.add_url_rule('/donation', 'donation',
                     donation_form, methods=["GET", "POST"])
    app.add_url_rule('/is_invoice_paid/<label>', 'ajax', ajax)
    bootstrap = Bootstrap(app)
    app.run("0.0.0.0", port=port)
    return


jobs = {}


def start_server(port):
    if port in jobs:
        return False, "server already running"

    p = multiprocessing.Process(
        target=worker, args=[port], name="server on port {}".format(port))
    p.daemon = True

    jobs[port] = p
    p.start()

    return True


def stop_server(port):
    if port in jobs:
        jobs[port].terminate()
        del jobs[port]
        return True
    else:
        return False


def json_donation_server(request, command="start", port=8088):
    commands = {"start", "stop", "restart", "list"}

    # if command unknown make start our default command
    if command not in commands:
        command = "start"

    # if port not an integer make 8088 as default
    try:
        port = int(port)
    except:
        port = 8088

    if command == "list":
        return "servers running on the following ports: {}".format(list(jobs.keys()))

    if command == "start":
        if port in jobs:
            return "Server already running on port {}. Maybe restart the server?".format(port)
        suc = start_server(port)
        if suc:
            return "started server successfully on port {}".format(port)
        else:
            return "Could not start server on port {}".format(port)

    if command == "stop":
        if stop_server(port):
            return "stopped server on port{}".format(port)
        else:
            return "could not stop the server"

    if command == "restart":
        stop_server(port)
        suc = start_server(port)
        if suc:
            return "started server successfully on port {}".format(port)
        else:
            return "Could not start server on port {}".format(port)


def json_getmanifest(request):

    verbose = """Starts a donationserver with {start/stop/restart} on {port}.

A Simple HTTP Server is created that can serve a donation webpage and allow to issue invoices.
The plugin takes one of the following three commands {start/stop/restart} as the first agument
By default the plugin starts the server on port 8088. This can however be changed with the
port argument.
"""

    return {
        "options": [
        ],
        "rpcmethods": [
            {
                "name": "donationserver",
                "description": "Starts a donationserver with {start/stop/restart} on {port}.",
                "long_description": verbose
            },
        ]
    }


def json_init(request, options, configuration):
    """The main daemon is telling us the relevant cli options
    """
    global rpc_interface

    basedir = request['params']['configuration']['lightning-dir']
    rpc_filename = request['params']['configuration']['rpc-filename']
    path = join(basedir, rpc_filename)

    rpc_interface = LightningRpc(path)

    return "ok"


methods = {
    'getmanifest': json_getmanifest,
    'init': json_init,
    'donationserver': json_donation_server,


}
# FIXME: for debugging
# start_server(8088)

partial = ""
for l in sys.stdin:
    try:
        partial += l
        request = json.loads(partial)
    except Exception:
        continue

    result = None
    method = methods[request['method']]
    params = request['params']
    try:
        if isinstance(params, dict):
            result = method(request, **params)
        else:
            result = method(request, *params)
        result = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request['id']
        }
    except Exception as e:
        result = {
            "jsonrpc": "2.0",
            "error": "Error while processing {}".format(request['method']),
            "id": request['id']
        }

    json.dump(result, fp=sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()
    partial = ""
