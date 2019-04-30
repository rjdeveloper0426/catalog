#!/usr/bin/env python
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify  # noqa

# CRUD Database function
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Catalog, Item, User

# New imports for this step
from flask import session as login_session
import random
import string

# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

# Connect to Database and create database session
engine = create_engine(
    'sqlite:///catalogitemwithusers.db?check_same_thread=False'
    )
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'  # noqa
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response

# JSON APIs to view Catalog Information
@app.route('/catalog/JSON')
def catalogJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(catalogs=[c.serialize for c in catalogs])


@app.route('/catalog/<int:catalog_id>/item/JSON')
def catalogItemJSON(catalog_id):
    catalogs = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/JSON')
def itemJSON(catalog_id, item_id):
    item_id = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item_id=item_id.serialize)

# Show all Catalog
@app.route('/')
@app.route('/catalog')
def catalog():
    catalogs = session.query(Catalog).all()
    if 'username' not in login_session:
        return render_template('publiccatalog.html', catalogs=catalogs)
    else:
        return render_template('catalog.html', catalogs=catalogs)

# Create new catalog
@app.route('/catalog/add', methods=['GET', 'POST'])
def addCatalog():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_catalog = Catalog(name=request.form['name'], user_id=login_session['user_id'])  # noqa
        session.add(new_catalog)
        flash('New Catalog %s Successfully Created' % new_catalog.name)
        session.commit()
        return redirect(url_for('catalog'))
    else:
        return render_template('addcatalog.html')

# Edit a catalog
@app.route('/catalog/<int:catalog_id>/edit', methods=['GET', 'POST'])
def editCatalog(catalog_id):
    catalogs = session.query(Catalog).all()
    edit_catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if edit_catalog.user_id != login_session['user_id']:
        return "You are not the authorized user to edit this catalog."
    if request.method == 'POST':
        if request.form['name']:
            edit_catalog.name = request.form['name']
            session.add(edit_catalog)
            flash('%s Successfully Edited' % edit_catalog.name)
            session.commit()
        return redirect(url_for('catalog', catalogs=catalogs))
    else:
        return render_template('editcatalog.html', catalog=edit_catalog)

# Delete a catalog
@app.route('/catalog/<int:catalog_id>/delete', methods=['GET', 'POST'])
def deleteCatalog(catalog_id):
    catalogs = session.query(Catalog).all()
    delete_catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delete_catalog.user_id != login_session['user_id']:
        return "You are not the authorized user to delete this catalog."
    if request.method == 'POST':
        session.delete(delete_catalog)
        flash('%s successfully deleted' % delete_catalog.name)
        session.commit()
        return redirect(url_for('catalog', catalogs=catalogs))
    else:
        return render_template('deletecatalog.html', catalog=delete_catalog)

# Show a Catalog Item
@app.route('/catalog/<int:catalog_id>/')
@app.route('/catalog/<int:catalog_id>/item')
def item(catalog_id):
    catalog_id = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(Item).filter_by(catalog_id=catalog_id.id).all()
    creator = getUserInfo(catalog_id.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:  # noqa
        return render_template('publicitem.html', items=items, catalog_id=catalog_id, creator=creator)  # noqa
    else:
        return render_template('item.html', items=items, catalog_id=catalog_id, creator=creator)  # noqa

# Create a new catalog item
@app.route('/catalog/<int:catalog_id>/item/add', methods=['GET', 'POST'])
def addItem(catalog_id):
    if 'username' not in login_session:
        return redirect('/login')
    catalog_id = session.query(Catalog).filter_by(id=catalog_id).one()
    if request.method == 'POST':
        new_item = Item(name=request.form['name'], description=request.form['description'], catalog_id=catalog_id.id)  # noqa
        session.add(new_item)
        session.commit()
        flash('New %s Item Successfully Created' % (new_item.name))
        return redirect(url_for('item', catalog_id=catalog_id.id))
    else:
        return render_template('additem.html', catalog_id=catalog_id)

# Edit a catalog item
@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])  # noqa
def editItem(catalog_id, item_id):
    edit_item = session.query(Item).filter_by(id=item_id).one()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "You are not the authorized user to edit this item."
    if request.method == 'POST':
        if request.form['name']:
            edit_item.name = request.form['name']
        if request.form['description']:
            edit_item.description = request.form['description']
            session.add(edit_item)
            session.commit()
            flash('Item %s successfully edited' % (edit_item.name))
        return redirect(url_for('item', catalog_id=catalog_id))
    else:
        return render_template('edititem.html', catalog_id=catalog_id, item_id=item_id, item=edit_item)  # noqa

# Delete a catalog item
@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/delete', methods=['GET', 'POST'])  # noqa
def deleteItem(catalog_id, item_id):
    delete_item = session.query(Item).filter_by(id=item_id).one()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    if login_session['user_id'] != catalog.user_id:
        return "You are not the authorized user to delete this item."
    if request.method == 'POST':
        session.delete(delete_item)
        session.commit()
        flash('Item successfully deleted')
        return redirect(url_for('item', catalog_id=catalog_id))
    else:
        return render_template('deleteitem.html', catalog_id=catalog_id, item_id=item_id, item=delete_item)  # noqa

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('catalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('catalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
