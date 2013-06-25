from flask import Flask, request, redirect, url_for, session, flash, g, \
    render_template, abort
from flask_oauth import OAuth
from settings import *
from pocket import Pocket
import hashlib
import requests
import json
import hmac
import hashlib
from time import time
app = Flask(__name__)
app.config.update(FLASK_CONFIG)
app.secret_key = "YOUR_FLASK_SECRET"
app.jinja_env.add_extension('jinja2.ext.loopcontrols')
oauth = OAuth()

from feedlight.models import Document, User, DocumentSummary
from feedlight.providers import twitter_feed, facebook_feed
from bson.objectid import ObjectId


# Jinja2 filters
from lxml.html.clean import Cleaner
from lxml.etree import XMLSyntaxError


cleaner = Cleaner(scripts=True, javascript=True, comments=True,
    style=True, meta=True, page_structure=True, embedded=True, frames=True,
    forms=True, annoying_tags=True, safe_attrs_only=True, add_nofollow=True,
    safe_attrs=[])


def generate_intercom_user_hash(user_id_or_email):
    return hmac.new(INTERCOM_APP_TOKEN, user_id_or_email, digestmod=hashlib.sha256).hexdigest()


def make_summary(text):
    if not text:
        return ""
    return text[:200] + "..."


def md5(url):
    return hashlib.md5(url.lower()).hexdigest()


def extract_domain(url):
    return '/'.join(url.split('/')[:3])


def primary_image(media):
    for m in media:
        if m['type'] == 'image' and m.get('primary'):
            return m

app.jinja_env.filters['md5'] = md5
app.jinja_env.filters['make_summary'] = make_summary
app.jinja_env.filters['extract_domain'] = extract_domain
app.jinja_env.filters['primary_image'] = primary_image
app.jinja_env.filters['clean'] = cleaner.clean_html


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        u = User.find_one({'_id': ObjectId(session['user_id'])})
        if not u: # Problem
            return logout()
        g.user = u
        g.intercom_hash = generate_intercom_user_hash(u.email)


@app.route('/login', methods=('POST',))
def login():
    # The request has to have an assertion for us to verify
    if 'assertion' not in request.form:
        abort(400)

    # Send the assertion to Mozilla's verifier service.
    data = {'assertion': request.form['assertion'], 'audience': app.config['audience']}
    resp = requests.post('https://verifier.login.persona.org/verify', data=data, verify=True)

    # Did the verifier respond?
    if resp.ok:
        # Parse the response
        verification_data = json.loads(resp.content)

        # Check if the assertion was valid
        if verification_data['status'] == 'okay':
            # Check if current user exists
            u = User.find_one({'email': verification_data['email']})

            # If it's a new user, create it
            if not u:
                email = verification_data['email'].strip().lower()
                u = User({'email': email,
                          'created_at': int(time()), 'meta': {},
                          'gravatar_hash': md5(email),
                          'credentials': {}})
                u.save()

            session['user_id'] = str(u._id)

            session.update({'email': verification_data['email']})
            return ""

    # Oops, something failed. Abort.
    abort(500)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('user_id', None)
    return redirect(request.referrer or url_for('index'))


@app.route('/')
def index():
    if g.user is None:
        return render_template('home.html')
    else:
        filter_dict = {'user': g.user._id, 'read': False}
        links = Document.find(filter_dict).sort('last_source_date', -1).limit(20)
        links_count = Document.find(filter_dict).count()
        return render_template('index.html', links=links, links_count=links_count)


# @app.route('/read/<link_id>')
# def read(link_id):
#     link = Document.find_one({'user': g.user._id, '_id': ObjectId(link_id)})
#     if not link:
#         return 'Link not found', 404
#     return render_template('read.html', link=link)


@app.route('/read/<link_id>')
def read(link_id):
    read = request.args.get('read', True)

    if read == 'False':
        read = False
    else:
        read = True

    link = Document.find_one({'user': g.user._id, '_id': ObjectId(link_id)})
    if link:
        link.read = read
        link.save()
    return "OK"


@app.route('/push_to_pocket/<link_id>')
def push_to_pocket(link_id):
    link = Document.find_one({'user': g.user._id, '_id': ObjectId(link_id)})
    if link:
        user = User.find_one({'_id': link.user})
        pocket_instance = Pocket(POCKET_APP_TOKEN,
                                 user.credentials['pocket']['token'])
        pocket_instance.add(link.url, wait=False)
        link.read = True
        link.save()
    return "OK"


@app.route("/profile")
def hello(user_id):
    base = "%s documents.<ol>" % Document.find(user=user_id).count()
    for doc in Document.find(user=user_id):
        base += "<li>Document url: %s. Shared %s times. Sources: %s</li>" % (doc.url, len(doc.sources), doc.sources.keys())
    base += "</ol>"
    return base


#
# Common social network
#


def process_authorized(network, resp, get_info, token_key, secret_key):
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        return False, redirect(next_url)

    infos = get_info(resp)

    # User is logged, attach network credentials
    if g.user is not None:
        link = True

        if g.user.credentials.get(network):
            link = False

        g.user.credentials[network] = {'token': resp.get(token_key),
                                       'secret': resp.get(secret_key)}
        g.user.meta[network] = infos
        g.user.save()
        return link, redirect(next_url)

    username = infos['username']
    user = User.find_one({'meta.%s.username' % network: username})

    # user never signed on
    if user is None:
        assert False, "User couldn't create an account without persona"
        user = User()
        user.meta = {network: infos}
        user.update(infos)
        user.credentials = {}

    # in any case we update the authenciation token in the db
    # In case the user temporarily revoked access we will have
    # new tokens here.
    link = True
    if user.credentials.get(network):
        link = False
    user.credentials[network] = {'token': resp.get(token_key),
                                 'secret': resp.get(secret_key)}
    user.save()

    session['user_id'] = user._id
    return link, redirect(next_url)


#
# Twitter
#

twitter = oauth.remote_app('twitter',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key=TWITTER_APP_TOKEN,
    consumer_secret=TWITTER_APP_SECRET
)


@twitter.tokengetter
def get_twitter_token():
    user = g.user
    if user is not None and user.credentials.get('twitter') is not None:
        return user.credential['twitter']['token'], user.credential['twitter']['secret']


@app.route('/twitter_login')
def twitter_login():
    """Calling into authorize will cause the OpenID auth machinery to kick
    in.  When all worked out as expected, the remote application will
    redirect back to the callback URL provided.
    """
    return twitter.authorize(callback=url_for('twitter_authorized',
                             next=request.args.get('next') or
                             request.referrer or None))


@app.route('/twitter_authorized')
@twitter.authorized_handler
def twitter_authorized(resp):
    """Called after authorization.  After this function finished handling,
    the OAuth information is removed from the session again.  When this
    happened, the tokengetter from above is used to retrieve the oauth
    token and secret.

    Because the remote application could have re-authorized the application
    it is necessary to update the values in the database.

    If the application redirected back after denying, the response passed
    to the function will be `None`.  Otherwise a dictionary with the values
    the application submitted.  Note that Twitter itself does not really
    redirect back unless the user clicks on the application name.
    """
    creation_or_link, redirect = process_authorized('twitter', resp,
        lambda resp: {'username': resp['screen_name']},
        'oauth_token', 'oauth_token_secret')
    if creation_or_link:
        twitter_feed.apply_async(args=[session['user_id']])
    return redirect

#
# Facebook
#


facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_TOKEN,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'read_stream'}
)


@facebook.tokengetter
def get_facebook_token():
    user = g.user
    if user is not None and user.credentials.get('facebook') is not None:
        return user.credential['facebook']['token'], user.credential['facebook']['secret']


@app.route('/facebook_login')
def facebook_login():
    """Calling into authorize will cause the OpenID auth machinery to kick
    in.  When all worked out as expected, the remote application will
    redirect back to the callback URL provided.
    """
    return facebook.authorize(callback=url_for('facebook_authorized',
                              next=request.args.get('next') or request.referrer
                              or None, _external=True))


@app.route('/facebook_authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    def get_info(resp):
        # raise Exception(resp)
        facebook.tokengetter_func = lambda: (resp['access_token'], '')
        data = facebook.get('/me').data
        facebook.tokengetter_func = None
        user_id = int(data['id'])
        return {'username': data['first_name']}

    creation_or_link, redirect = process_authorized('facebook', resp, get_info,
                                                    'access_token', None)
    if creation_or_link:
        facebook_feed.apply_async(args=[session['user_id']])
    return redirect


#
# Getpocket
#


@app.route('/pocket_login')
def pocket_login():
    """Calling into authorize will cause the OpenID auth machinery to kick
    in.  When all worked out as expected, the remote application will
    redirect back to the callback URL provided.
    """
    redirect_uri = url_for('pocket_authorized', _external=True)
    request_token = Pocket.get_request_token(consumer_key=POCKET_APP_TOKEN,
                                             redirect_uri=redirect_uri)
    session['request_token'] = request_token
    return redirect(Pocket.get_auth_url(code=request_token,
                                        redirect_uri=redirect_uri))


@app.route('/pocket_authorized')
def pocket_authorized():
    access_token = Pocket.get_access_token(consumer_key=POCKET_APP_TOKEN,
                                           code=session['request_token'])
    resp = {'oauth_token': access_token, 'oauth_secret': ''}
    creation_or_link, redirect = process_authorized('pocket', resp,
        lambda x: True, 'oauth_token', 'oauth_token_secret')
    return redirect


def clean():
    User.col.remove()
    Document.col.remove()
    DocumentSummary.col.remove()
    User.con['tasks']['messages'].remove()


if __name__ == "__main__":
    # clean()
    app.debug = True
    app.run(host='0.0.0.0')
