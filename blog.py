import webapp2
import logging
import re
import jinja2
import os
import time
import cgi
import hashlib
import binascii
from google.appengine.ext import db

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'])

class MyHandler(webapp2.RequestHandler):
    def write(self, *writeArgs):
        self.response.write(" : ".join(writeArgs))

    def render_str(self, template, **params):
        tplt = JINJA_ENVIRONMENT.get_template('templates/'+template)
        return tplt.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

secureKeyFile = open("securekey.txt","r")
secureKey = secureKeyFile.read()

def make_secure_val(s):
    hash = hashlib.pbkdf2_hmac('sha256', b's', b'secureKey', 100000) ## Uses 100000 rounds of a sha256 hash
    hashHex = binascii.hexlify(hash) ## Converts binary hash to hex for storage
    output = str(s) + "|" + str(hashHex)
    return output

def check_secure_val(h):
    barLoc = h.find('|')
    s = h[:barLoc]
    if (make_secure_val(s) == h):
        return s
    else:
        return None

def make_salt():
    salt = os.urandom(8) ## Returns a string of 8 random bytes suitable for cryptographic use
    return salt

def make_pw_hash(pw, salt=None):
    if salt is None:
        salt = make_salt()
    hash = hashlib.pbkdf2_hmac('sha256', b'pw', b'salt', 100000) ## Uses 100000 rounds of a sha256 hash
    hashHex = binascii.hexlify(hash) ## Converts binary hash to hex for storage
    output = str(hashHex) + "|" + str(salt)
    return output

def valid_pw(name, pw, h):
    barLoc = h.find('|')
    salt = h[barLoc:]
    return (make_pw_hash(pw, salt) == h)

USER_RE = re.compile(r'^[\w\-]{3,20}$')
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r'^\S{3,20}$')
def valid_password(username):
    return PASSWORD_RE.match(username)

EMAIL_RE = re.compile(r'^(\S+@\S+\.\S+)?$')
def valid_email(username):
    return EMAIL_RE.match(username)

def escape_html(s):
   return cgi.escape(s, quote = True)

class PostDB(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    owner = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class Users(db.Model):
    username = db.StringProperty()
    passwordHash = db.StringProperty()
    email = db.StringProperty()

class HomeRedirect(MyHandler):
    def get(self):
        self.redirect('/blog/profile')

class Signup(MyHandler):
    def write_signup(self, username_error_msg="", password_error_msg="", verify_error_msg="", email_error_msg="", user_username="", user_email=""):
        signupValues = {"error_username": username_error_msg,
                                      "error_password": password_error_msg,
                                      "error_verify"  : verify_error_msg,
                                      "error_email"   : email_error_msg,
                                      "username_value": escape_html(user_username),
                                      "email_value"   : escape_html(user_email)}

        signup = JINJA_ENVIRONMENT.get_template('templates/signup.html')
        self.response.write(signup.render(signupValues))

    def get(self):
        logging.info("********** Signup GET **********")
        self.response.headers['Content-Type'] = 'text/html'
        self.write_signup()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        user_username_v = valid_username(user_username)
        user_password_v = valid_password(user_password)
        user_email_v = valid_email(user_email)
        user_verify_v = True
        user_exists_v = True

        username_error_msg = password_error_msg = verify_error_msg = email_error_msg = ""

        userInDB = db.GqlQuery("SELECT * FROM Users WHERE username = '%s'" % user_username).get()

        if (userInDB is not None):
            logging.info("USERINDB: " + userInDB.username)
            user_exists_v = False
            username_error_msg = "That user already exists."

        if not(user_username_v):
            username_error_msg = "That's not a valid username."

        if (user_password != user_verify):
            user_verify_v = False
            password_error_msg = "Passwords do not match."
        elif not(user_password_v):
            password_error_msg = "That's not a valid password."
        if (user_email != "") and not(user_email_v):
            email_error_msg = "That's not a valid email."

        if not(user_username_v and user_password_v and user_verify_v and ((user_email == "") or user_email_v) and (user_password == user_verify) and user_exists_v):
            self.write_signup(username_error_msg, password_error_msg, verify_error_msg, email_error_msg, user_username, user_email)
        else:
            ##User signup is valid
            userInst = Users()
            userInst.username = user_username
            userInst.passwordHash = make_pw_hash(user_username, user_password)
            userInst.email = user_email
            userInst.put()
            time.sleep(.2)
            userID = userInst.key().id()
            userIDSecure = make_secure_val(userID)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % userIDSecure)
            self.redirect('/blog/profile')

class Login(MyHandler):
    def write_login(self, login_error_msg=""):
        loginValues = {"login_error": login_error_msg}
        login = JINJA_ENVIRONMENT.get_template('templates/login.html')
        self.response.write(login.render(loginValues))

    def get(self):
        logging.info("********** Login GET **********")
        self.response.headers['Content-Type'] = 'text/html'
        self.write_login()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = db.GqlQuery("SELECT * FROM Users WHERE username = '%s'" % username).get()

        if (user is not None):
            ##User exists
            hash = user.passwordHash
            if (valid_pw(username, password, hash) is not None):
                ##Username and password are valid
                userID = user.key().id()
                userIDSecure = make_secure_val(userID)
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % userIDSecure)
                self.redirect('/blog/profile')

        login_error_msg = "Invalid login"
        self.write_login(login_error_msg)

class Logout(MyHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/login')

class Profile(MyHandler):
    def write_profile(self, username=""):
        posts = db.GqlQuery("SELECT * FROM PostDB WHERE owner = '%s' ORDER BY created DESC limit 10" % username)
        profileValues = {"username": username}
        profile = JINJA_ENVIRONMENT.get_template('templates/profile.html')
        self.response.write(profile.render(profileValues, posts=posts))

    def get(self):
        logging.info("********** Profile GET **********")
        self.response.headers['Content-Type'] = 'text/html'

        userIDHashed = self.request.cookies.get('user_id', '0')
        userID = check_secure_val(userIDHashed)
        if (userID == None):
            self.redirect('/blog/login')
        else:
            user = Users.get_by_id(int(userID))
            self.write_profile(user.username)

class Blog(MyHandler):
    def renderPosts(self):
        posts = db.GqlQuery("SELECT * FROM PostDB ORDER BY created DESC limit 10")
        self.render("posts.html", posts=posts)

    def get(self):
        logging.info("********** Blog GET **********")
        self.response.headers['Content-Type'] = 'text/html'
        self.renderPosts();

class NewPost(MyHandler):
    def renderNewPost(self, inputError=""):
        pageValues = {"ph_error": inputError}
        page = JINJA_ENVIRONMENT.get_template('templates/newpost.html')
        self.response.write(page.render(pageValues))

    def get(self):
        logging.info("********** NewPost GET **********")
        self.renderNewPost()

    def post(self):
        logging.info("********** NewPost POST **********")
        subject = self.request.get("subject")
        content = self.request.get("content")

        if ((not subject) or (not content)):
            inputError = "Please provide both a title and post content"
            self.renderNewPost(inputError)
        else:
            userIDHashed = self.request.cookies.get('user_id', '0')
            userID = check_secure_val(userIDHashed)
            if (userID == None):
                self.redirect('/blog/login')
            else:
                user = Users.get_by_id(int(userID))

            postInst = PostDB()
            postInst.subject = subject
            postInst.content = content
            postInst.owner = user.username
            postInst.put()
            time.sleep(.2)
            postID = postInst.key().id()
            self.redirect('/blog/' + str(postID))

class PostHandler(MyHandler):
    def renderPost(self, posts):
        self.render("posts.html", posts=posts)

    def get(self, postID):
        logging.info("********** PostHandler GET **********")

        post = PostDB.get_by_id(int(postID))
        posts = [post]
        self.renderPost(posts)


application = webapp2.WSGIApplication([
    ('/', HomeRedirect),
    (r'/blog/signup/?', Signup),
    (r'/blog/login/?', Login),
    (r'/blog/logout/?', Logout),
    (r'/blog/profile/?', Profile),
    (r'/blog/?', Blog),
    ('/blog/newpost/?', NewPost),
    (r'/blog/(\d+)/?', PostHandler)
], debug=True)
