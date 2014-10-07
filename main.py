#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import urllib2
import time
import random
import hashlib
import hmac
import string

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Entries(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)

# user stuff

class Users(db.Model):
    username = db.StringProperty(required = True)
    hashedpw = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

SECRET = 'vewyvewyVEWYseekWit!*'
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_salt():
    # make 5 char salt
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt):
    if salt == '':
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.rsplit('|',1)[1]
    return h == make_pw_hash(name, pw, salt)

def check_user(self):
    seekrit = self.request.cookies.get("username")
    if not seekrit:
        return False
    else:
        username = check_secure_val(seekrit)
        #if username:
        if Users.gql("WHERE username = :1", username).get():
             return username
        else:
             return False

QT = {}

def wiki_entry(name):
    entry = memcache.get(name)
    if entry is None:
        entryquery = db.GqlQuery("SELECT * "
                             "FROM Entries "
                             "WHERE name = :1 " # safer transaction
                             #"WHERE ANCESTOR IS :1 " # safer transaction
                             "ORDER BY created DESC "
                             "LIMIT 1", name) 
                             # , bblog_key) #required key; how to?
        entry = entryquery.get()
        if entry:
            memcache.set(name, entry)
            QT[name] = time.time()
    return entry

def wiki_version(entry_name, entry_id):
    entry_version = entry_name + '?id=' + entry_id
    entry = memcache.get(entry_version)
    if entry is None:
        entry = Entries.get_by_id(long(entry_id))
        if entry:
            memcache.set(entry_version, entry)
            QT[entry_version] = time.time()
    return entry, entry_version

class WikiPage(Handler):
    def get(self, entry_name):
        entry_id = self.request.get('id')
        if entry_id:
            entry, entry_version = wiki_version(entry_name, entry_id)
        else:
            entry = wiki_entry(name=entry_name)
            entry_version = entry_name
        if entry:
            if entry_version in QT:
                age = "last queried %s seconds ago" % str(int(round(time.time() - QT[entry_version])))
            else:
                age = 'last query unknown'
            self.render("page.html", e = entry, age=age)
        else:
            if entry_name == "/":
                name = entry_name
                content = 'welcome to candle-wiki!'
                e = Entries(name = name, content = content)
                e.put()
                memcache.set(name, entry)
                QT[name] = time.time()
                age = "newly entered!"
                self.render("page.html", e = e, age=age)
            else:
                editor = check_user(self)
                if editor:
                    self.redirect("/_edit" + entry_name)
                else:
                    self.redirect("/login")

class EditPage(Handler):
    def render_editentry(self, name="", content="", error=""):
        self.render("editentry.html", name=name, content=content, error=error)

    def get(self, entry_name):
        editor = check_user(self)
        if editor:
            entry_id = self.request.get('id')
            if entry_id:
                entry, entry_version = wiki_version(entry_name, entry_id)
            else:
                entry = wiki_entry(name=entry_name)
            if entry:
                name = entry.name
                content = entry.content
            else:
                name = entry_name
                content = ""
            self.render_editentry(name=name, content=content)
        else:
            self.redirect("/login")

    def post(self, entry_name):
        editor = check_user(self)
        if editor:
            content = self.request.get("content")
            name = entry_name
            if name:
                entry = Entries(name = name, content = content)
                entry.put() 
                memcache.set(name, entry)
                QT[name] = time.time()
                self.redirect("%s" % name)
            else:
                error = "oops! we need a valid name."
                self.render_editentry(name, content, error)
        else:
            self.redirect("/login")

class PageHistory(Handler):
    def get(self, entryID):
        key = "/_history" + entryID
        history = memcache.get(key)
        if history is None:
            history = db.GqlQuery("SELECT * "
                             "FROM Entries "
                             "WHERE name = :1 "
                             #"WHERE ANCESTOR IS :1 " # safer transaction
                             "ORDER BY created DESC", entryID)
            history = list(history) 
            memcache.set(key, history)
            QT[key] = time.time()
        self.render("history.html", name = entryID, history = history, age = "")

class Signup(Handler):
    def render_signup(self, username="", error_u="", error_p="",email="",error_e=''):
        self.render("signup.html", username=username, error_u=error_u, error_p=error_p, email=email, error_e=error_e)
    def get(self):
        self.render_signup()
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        if valid_username(username):
            if Users.gql("WHERE username = :1", username).get():
                error_u = "Oops! That username is already taken."
            else:
                error_u = ''
        else:
            error_u = "Oops! Your username is invalid."
        if password == verify:
            if valid_password(password):
                error_p = ''
            else:
                error_p = "Oops! Your password is invalid."
        else:
            error_p = "Oops! Your password entries don't match."
        if email:
            if valid_email(email):
                error_e = ''
            else:
                error_e = "Oops! Your e-mail entry is invalid."
        else:
            email = ''
            error_e = ''
        if error_u == '' and error_p == '' and error_e == '':
            hashedpw = make_pw_hash(name = username, pw = password, salt = '')
            u = Users(username = username, hashedpw = hashedpw, email = email)
            u.put()
            seekrit = str(make_secure_val(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/'%seekrit)
            self.redirect("/")
        else:
            self.render_signup(username,error_u,error_p,email,error_e)

class Login(Handler):
    def render_login(self, username="", error=""):
        self.render("login.html", username=username, error=error)
    def get(self):
        self.render_login()
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if valid_username(username) and valid_password(password):
            u = Users.gql("WHERE username = :1", username).get()
            if not u:
                error = "Oops!  Invalid login!"
            else:
                if valid_pw(name = username, pw = password, h = u.hashedpw):
                    error = ''
                else:
                    error = "Oops! Invalid login!"
        else:
            error = "Oops! Invalid login!"
        if error == '': 
            seekrit = str(make_secure_val(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/'%seekrit)
            self.redirect("/")
        else:
            self.render_login(username,error)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/'%'')
        self.redirect("/")

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, PageHistory),
                               (PAGE_RE, WikiPage)
                               ],
                               debug=True)
