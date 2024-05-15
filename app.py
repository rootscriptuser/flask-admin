from flask_sqlalchemy import SQLAlchemy

from flask import Flask, render_template, url_for, redirect, request, flash
from flask_admin import Admin, AdminIndexView, expose, expose_plugview, BaseView

from flask_admin.contrib.sqla import ModelView

from flask_bootstrap import Bootstrap5

import flask_login

import folium

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

app =Flask(__name__)

app.config['FLASK_ADMIN_SWATCH'] = 'cosmo' #bootswatch/3
app.config['SECRET_KEY'] = 'k'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/mint/Desktop/ultimate/admin.db'
app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'cosmo'
#app.secret_key = "super secret string"  # Change this!

bootstrap = Bootstrap5(app)
db = SQLAlchemy(app)

class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not flask_login.current_user.is_authenticated:
            return redirect(url_for('login'))
        #flash('Logged in successfully.')
        return super(MyAdminIndexView, self).index()

"""
    @expose('/rpt/')
    def rpt(self):
        if not flask_login.current_user.is_authenticated:
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()

    @expose('/user/')
    def usr(self):
        if not flask_login.current_user.is_authenticated:
            return redirect(url_for('login'))
        return super(MyAdminIndexView, self).index()
"""
class otherViews(ModelView):

    def is_accessible(self):
        return flask_login.current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
# redirect to login page if user doesn't have access
        return redirect(url_for('login', next=request.url))    


login_manager = flask_login.LoginManager()
login_manager.init_app(app)
#login_manager.login_view = 'admin.index'

class User(db.Model, flask_login.UserMixin):
    """An admin user capable of viewing reports.

    :param str email: email address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String)
    password = db.Column(db.String)


class RPT( db.Model):
    __tablename__ = "rpt"
    id = db.Column(db.Integer, primary_key=True)
    call = db.Column(db.String, unique=True, nullable=False)
    in_freq  = db.Column(db.String, nullable=False)
    out_freq  = db.Column(db.String, nullable=False)
    in_sub  = db.Column(db.String, nullable=False)
    out_sub  = db.Column(db.String, nullable=False)

admin = Admin(app, name='Admin', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(otherViews(User, db.session ))
admin.add_view(otherViews(RPT, db.session ))

@login_manager.user_loader
def user_loader(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (email) user to retrieve

    """
    return User.query.get(user_id)


@app.get("/login")
def login():
    return render_template('login.html')

@app.post("/login")
def loginP():
    email=request.form["email"]
    password=request.form["password"]
    user = User.query.filter_by(email=email).first() 
    if email == None or password != user.password: return "potato" # Check if the password entered is the # same as the user's password
    print(user)
    flask_login.login_user(user)    
    return redirect(url_for('admin.index'))


@app.route("/logout")
def logout():
    flask_login.logout_user()
    return "Logged out"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/rpt")
def rpt():
    classes=["table-primary","table-secondary","table-success","table-dark","table-info","table-warning","table-light"]
    all_rpt= RPT.query.order_by(RPT.call).all()
    return render_template("rpt.html", all_rpt=all_rpt, classes=classes)

if __name__ == '__main__':
    app.run()
