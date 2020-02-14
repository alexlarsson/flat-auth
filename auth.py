#!env python3

# Run with something like:
# FLASK_APP=auth.py flask-3 run --host=0.0.0.0 --port=7777

from flask import Flask, request, render_template, session, redirect, url_for
from flask_restful import Resource, Api, abort, reqparse
from sqlalchemy import create_engine, select
import json
import jwt
from flask import jsonify
import secrets
import binascii
import urllib.parse
import requests
import base64
from datetime import datetime, timedelta
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey, DateTime

################# CONFIG ###########################


#Defaults
apiTokenLifetime = timedelta(days=30)
repoTokenLifetime = timedelta(minutes=10)

# Must set these options:
#  api_secret
#  repo_secret="secret"
#  googleClientID
#  googleClientSecret = 'qw9p0KcVP_3p80Dili4oFUFC'

from authconfig import api_secret, repo_secret, googleClientID, googleClientSecret

################# GLOBAL DEFINES ###########################

googleAauthorizeURL = 'https://accounts.google.com/o/oauth2/v2/auth'
googleTokenURL = 'https://www.googleapis.com/oauth2/v4/token';

################# DATABASE HELPERS ###########################

db_connect = create_engine('sqlite:///auth.db')

metadata = MetaData()
users = Table('users', metadata,
              Column('id', Integer, primary_key=True))
foreign_ids = Table('foreign_ids', metadata,
                    Column('id', String, primary_key=True),
                    Column('user_id', None, ForeignKey('users.id')))
purchases = Table('purchases', metadata,
                  Column('app_id', String, primary_key=True),
                  Column('user_id', None, ForeignKey('users.id')),
                  Column('until', DateTime(timezone=True)))

metadata.create_all(db_connect)

def getUserByForeignId(foreign_id):
    result = db_connect.execute(select([foreign_ids]).where(foreign_ids.c.id == foreign_id))
    row = result.fetchone()
    return row

def ensureUserIDForForeignId(foreign_id):
    user = getUserByForeignId(foreign_id)
    if user:
        # Existing user
        print("Existing user %s for foreign id %s" % (user.user_id, foreign_id))
        user_id = user.user_id
    else:
        # New user
        result = db_connect.execute(users.insert())
        # TODO: Check result
        user_id = result.inserted_primary_key[0];
        # TODO: Check result
        result = db_connect.execute(foreign_ids.insert().values(id=foreign_id, user_id=user_id))
        print("Created new user %s for foreign id %s" % (user_id, foreign_id))
    return user_id

def isAppPurchasedByUser(app_id, user_id):
    result = db_connect.execute(select([purchases]).where(purchases.c.app_id == app_id and purchases.c.user_id == user_id))
    row = result.fetchone()
    if row == None:
        return False
    return row.until >= datetime.utcnow()

def markPurchasedByUser(app_id, user_id, num_seconds):
    db_connect.execute(purchases.delete().where(purchases.c.app_id == app_id and purchases.c.user_id == user_id))
    until = datetime.utcnow() + timedelta(seconds=num_seconds)
    result = db_connect.execute(purchases.insert().values(app_id = app_id, user_id = user_id, until = until))

################# BASIC APP ######################

app = Flask(__name__)
api = Api(app)

################# LOGIN ##########################

# This should probably use flask.session, but lets just hack this in memory for now
login_requests = {}

@app.route('/login')
def login():
    orig_redirect_uri = request.args.get('redirect_uri')
    if not orig_redirect_uri:
        abort(400)

    orig_state = request.args.get('state')

    state = binascii.hexlify(secrets.token_bytes(16)).decode('utf-8')
    login_requests[state] = {
        "redirect_uri": orig_redirect_uri,
        "state": orig_state,
    };

    google_url = "%s?%s" % (googleAauthorizeURL, urllib.parse.urlencode({
        'response_type': 'code',
        'client_id': googleClientID,
        'redirect_uri': url_for('login_google', _external=True),
        'scope': 'openid email',
        'state': state
    }))
    return render_template('login.html', google_url=google_url)

@app.route('/login_google')
def login_google():
    state = request.args.get('state')

    if not state in login_requests:
        abort(400)

    req = login_requests[state]

    code = request.args.get('code')
    verify_url = '%s?%s' % (googleTokenURL, urllib.parse.urlencode({
        'grant_type': 'authorization_code',
        'client_id': googleClientID,
        'client_secret': googleClientSecret,
        'redirect_uri': url_for('login_google', _external=True),
        'code': code,
    }))

    r = requests.post(verify_url)
    # TODO: Verify r.status_code
    res = r.json()

    access_token = res['access_token'] # weird
    id_token = res['id_token'] # jwt

    userinfo = jwt.decode(id_token, verify=False)
    foreign_id = "google:%s" % (userinfo['sub'])

    user_id = ensureUserIDForForeignId(foreign_id)
    token = jwt.encode({'sub': user_id, 'exp': datetime.utcnow() + apiTokenLifetime}, api_secret, algorithm='HS256')

    redirect_uri = '%s?%s' % (req["redirect_uri"], urllib.parse.urlencode ({
        'token': token,
        'state': req.get("state")
    }))

    return redirect(redirect_uri)

################# PURCHASE ##########################

purchase_requests = {}
next_purchase = 1

@app.route('/purchase/<purchaseid>')
def purchase(purchaseid):
    if not purchaseid in purchase_requests:
        abort(404)
    purchase_req = purchase_requests[purchaseid]

    orig_redirect_uri = request.args.get('redirect_uri')
    if not orig_redirect_uri:
        abort(400)

    orig_state = request.args.get('state')

    purchase_req["redirect_uri"] = orig_redirect_uri
    purchase_req["state"] = orig_state

    purchase_uri1 = url_for('purchased_done', purchaseid=purchaseid, secs=5,
                            _external=True)
    purchase_uri2 = url_for('purchased_done', purchaseid=purchaseid, secs=300,
                            _external=True)
    return render_template('purchase.html', app_id=purchase_req["id"], buy_url1=purchase_uri1, buy_url2=purchase_uri2)

@app.route('/purchase/<purchaseid>/done')
def purchased_done(purchaseid):
    if not purchaseid in purchase_requests:
        abort(404)
    purchase_req = purchase_requests[purchaseid]

    secs = request.args.get("secs")
    redirect_uri = '%s?%s' % (purchase_req["redirect_uri"], urllib.parse.urlencode ({
        'state': purchase_req.get("state"),
        'redirect_uri': url_for('purchased_done_redirect', purchaseid=purchaseid,
                                _external=True),
    }))
    markPurchasedByUser(purchase_req["id"], purchase_req["userid"], int(secs))
    return redirect(redirect_uri)

@app.route('/purchase/<purchaseid>/done_redirect')
def purchased_done_redirect(purchaseid):
    if not purchaseid in purchase_requests:
        abort(404)
    purchase_req = purchase_requests[purchaseid]

    return render_template('purchase_done.html', app_id=purchase_req["id"])

################## API ###########################

def check_token(api):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        abort(403)
    if not auth_header.startswith("Bearer "):
        abort(403)
    token = auth_header[7:]
    decoded = jwt.decode(token, api_secret, algorithms='HS256')
    if not "sub" in decoded:
        abort(403)
    return decoded["sub"];

class GetToken(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('ids', required=False, type=str, action='append', default=[], location="json")
        args = parser.parse_args()

        userid = check_token(self)
        tokens = {}
        denied = []
        for id in args.ids:
            if isAppPurchasedByUser(id, userid):
                tokens[id] = jwt.encode({
                    'sub': 'users/%d' % userid,
                    'prefixes': [id],
                    'exp': datetime.utcnow() + repoTokenLifetime,
                    'name': 'auth.py',
                }, repo_secret, algorithm='HS256').decode('utf-8')
            else:
                denied.append(id)

        return {'tokens': tokens, 'denied': denied}

class BeginPurchase(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id', type=str, action='str', location="json", required=True)
        args = parser.parse_args()
        userid = check_token(self)

        purchaseid = binascii.hexlify(secrets.token_bytes(16)).decode('utf-8')

        purchase_requests[purchaseid] = {
            "id": args.id,
            "userid": userid,
        };

        return {'start_uri': 'purchase/%s' % (purchaseid) }

api.add_resource(GetToken, '/api/v1/get_tokens')
api.add_resource(BeginPurchase, '/api/v1/begin_purchase')


################## MAIN ENTRYPOINT ###########################

if __name__ == '__main__':
     app.run(port='7777',debug=True)
