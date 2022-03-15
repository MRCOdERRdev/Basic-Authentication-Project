from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, current_app,session
from werkzeug.security import generate_password_hash, check_password_hash
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

loginmanager=LoginManager()
app = Flask(__name__)
key="WTFMYLIFE"

loginmanager.init_app(app)
# app.secret_key=key
app.config['SECRET_KEY'] = key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    if (login_user):
        return render_template('index.html',logged_in=True)
    return render_template("index.html",logged_in=False)


@app.route('/register',methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get('name')
        email=request.form.get('email')
        password=request.form.get('password')
        try:
                
            hashed_password=generate_password_hash(password=password,method="sha256",salt_length=8)
            new_user=User(name=name,email=email,password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
        except :
            flash('You have already registered','error')
            return redirect('/register')    
        return render_template('secrets.html',data=name,logged_in=True)
    return render_template("register.html")


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
    
        user = User.query.filter_by(email=email).first()
        name=user.name
        #Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        #Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        #Email exists and password correct
        else:
            login_user(user)
            return render_template('secrets.html',data=name,logged_in=True)

    return render_template("login.html")

@loginmanager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name) 
    if not current_user.is_authenticated:
     return current_app.login_manager.unauthorized()
    render_template('index.html',logged_in=True)
    return render_template("secrets.html",logged_in=True)



@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

@app.route('/download/<path:filename>',methods=["GET","POST"])
@login_required
def download(filename):
    return send_from_directory(directory="static",filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
