from flask import Flask, session, url_for, redirect, request, abort
from flask.templating import render_template
from requests_oauthlib import OAuth2Session
import urllib
import requests
import os
import logging
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

oAuthSession = requests.Session()
APIKEY = os.getenv('DESTINY_APIKEY')

HEADERS = {"X-API-Key": APIKEY}

DESTINY_AUTHURL = 'https://www.bungie.net/en/OAuth/Authorize?client_id=33072&response_type=code&'
access_token_url = 'https://www.bungie.net/platform/app/GetAccessTokensFromCode/'
refresh_token_url = 'https://www.bungie.net/Platform/App/GetAccessTokensFromRefreshToken/'
destiny_secret = os.environ.get('DESTINY_SECRET')

@app.route('/')
@app.route('/home')
def index():
    return render_template('homepage.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/commands')
def commands():
    return render_template('commandspage.html')


@app.route('/suggestions')
def suggestions():
    return render_template('suggestions.html')

@app.route('/destiny/xur')
def xur():
    return "Xur isn't here for his will is not his own"


def make_authorization_url():
    from uuid import uuid4
    state = str(uuid4())
    session['state_token'] = state
    return state


def is_valid_state(state):
    saved_state = session['state_token']
    if state == saved_state:
        return True
    else:
        return False


def get_token(code):
    post_data = {'code': code}
    response = requests.post(access_token_url, json=post_data, headers=HEADERS)
    json = response.json()
    token_json = json['Response']['accessToken']['value']
    refresh_json = json['Response']['refreshToken']['value']
    refresh_ready = datetime.now() + timedelta(
        seconds=int(json['Response']['refreshToken']['readyin']))
    refresh_expired = datetime.now() + timedelta(
        seconds=int(json['Response']['refreshToken']['expires']))
    save_session(token_json)
    return token_json


def save_session(token_json):
    oAuthSession.headers['X-API-Key'] = APIKEY
    oAuthSession.headers['Authorization'] = 'Bearer ' + str(token_json)
    access_token = 'Bearer ' + str(token_json)


@app.route('/bungie_auth')
def bungie_auth():
    state = make_authorization_url()
    state_params = {'state': state}
    url = DESTINY_AUTHURL + urllib.urlencode(state_params)
    return render_template('bungie.html', url=url)


@app.route('/callback/bungie')
def bungie():
    error = request.args.get('error', '')
    if error:
        return '<h1>ERROR:</h1> ' + str(error)
    state = session.get('state_token')
    if not is_valid_state(state):
        logging.info("ERROR: States don't match")
        abort(403)
    session.pop('state_token', None)
    code = request.args.get('code')
    token = get_token(code)
    return redirect(url_for('index'))


@app.route('/twitch_auth')
def twitch_auth():
    return


@app.route('/callback/twitch')
def twitch():
    twitch = OAuth2Session()
    return redirect(url_for('index'))


discord_client_id = r'638446270469373972'
discord_redirect_uri = ''
discord_scope = ['identify', 'email']
discord_authorize_url = 'https://discordapp.com/api/oauth2/authorize'


@app.route('/login')
def login():
    oauth = OAuth2Session(
        discord_client_id,
        redirect_uri=discord_redirect_uri,
        scope=discord_scope)
    url, state = oauth.authorization_url(discord_authorize_url)
    session['state'] = state
    return render_template('discord', url=url)


@app.route('/callback/discord')
def discord():
    discord = OAuth2Session(
        discord_client_id,
        redirect_uri=discord_redirect_uri,
        state=session['state'],
        scope=discord_scope)
    token_url = 'https://discordapp.com/api/oauth2/token'
    
    return redirect(url_for('index'))


@app.route('/guildcount/<int:guilds>')
def guildcount(guilds):
    requests.post(
        'https://bots.ondiscord.xyz/bot-api/bots/638446270469373972/guilds',
        json={"guildcount": guilds},
        headers={'Authorization': os.environ.get('BOTSONDISCORD_KEY')})
    return redirect(url_for('.index'))


app.run(host="0.0.0.0", port=8080)