from flask import Flask, redirect, render_template, g, url_for, request, session, flash, url_for, logging, make_response
#from wtforms import Form, BooleanField, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
#from datetime import timedelta
from functools import wraps
import mysql.connector
import logging
import gc
                                                                            #pip freeze > requirements.txt
  
app = Flask(__name__)                                                           #creating an instance of the app
app.secret_key = 'my first app'                                                 #secret key required by session
#app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)
logging.basicConfig(level=logging.INFO)


#global COOKIE_TIME_OUT
#COOKIE_TIME_OUT = 60*60*24*7 #7 days
#COOKIE_TIME_OUT = 60*5 #5 minutes


                                                                                #config MYSQL
config = {
    'user': 'root',
    'password': 'OriafoDikodin1',
    'host': '127.0.0.1',
    'database': 'abraham',
}

                                                                                #home route
@app.route('/')
def Home():
   return render_template('home.html')

@app.route('/cookie/')
def cookie():
    res = make_response("Setting a cookie")
    res.set_cookie('foo', 'bar', max_age=60*60*24*365*2)
    return res

                                                                                #about-us route
@app.route('/About')
def About():
   return render_template('about.html')
                                                                                #render register form
@app.route('/Register')
def Register():
   return render_template('register.html')

                                                                                #registration route
@app.route('/register', methods=["GET","POST"])
def register():
    if request.method == "POST":                                                #check which method was used
        username  = request.form["username"]
        email = request.form["email"]
        password = sha256_crypt.hash((str(request.form["password"])))           #hashing and salting the password
        comfirm = request.form["comfirm password"]
        if sha256_crypt.verify(comfirm, password):
            db = mysql.connector.connect(**config)                                  #connecting to mysql database
            mycursor = db.cursor()                                                  #creating cursor object
            mycursor.execute("USE abraham")
            mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username]) #selecting "username" from the table "log_details" 
            data = mycursor.fetchone()                                              #fecting the first row of the output result in case of multi-rows
            if data != None:   
                logging.info('invalid credentials')
                error = 'invalid credentials'
                return render_template('register.html', error=error)                #logic to determine if the username exist in the database before so as to eliminate the case of having two similar username in the database
            else:
                mycursor.execute("INSERT INTO log_details (username, email, password) VALUES (%s, %s, %s)",(username, email, password))       
                db.commit()
                db.close()
                flash('registration successful')
                logging.info('registration successful')                         #log the details of the state of the application
                return render_template('login.html')
        else:
            logging.info('password does not match')
            error = 'Password does not match'
            return render_template('register.html', error=error)
    else:
        error = 'wrong method'
        logging.info('wrong method')
    return render_template('register.html', error=error)


def login_required(test):                                                           #using the login_required wrap decorator to restrict access to unauthorized users
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            logging.info('true')
            return test(*args, **kwargs)
        else:
            error = 'Unauthorised, please login'
            return render_template('login.html', error=error)
    return wrap

@app.route('/Dashboard')
@login_required                                                                     #using the wrap decorator on the dashboard page
def Dashboard():
   logging.info('dashboard')
   return render_template('dashboard.html')

def logout_required(test):                                                           #using the login_required wrap decorator to restrict access to unauthorized users
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' not in  session:
            logging.info('true')
            return test(*args, **kwargs)
        else:
            error = 'user currently login, Pleae Logout'
            return render_template('dashboard.html', error=error)
    return wrap

@app.route('/Login')
def Login():
    return render_template('login.html')


@app.route('/login', methods=['GET','POST'])
@logout_required
def login():
    error = None
    if request.method == 'POST':
        username = request.form["username"]
        password_insert = request.form["password"]
        remember = request.form.getlist('Remember_me')
        db = mysql.connector.connect(**config)
        mycursor = db.cursor()
        mycursor.execute("USE abraham")
        mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username])    
        data = mycursor.fetchone()
        if data != 0:                                                        #logic to determine if the username is in the database
            password = data[2]
            if sha256_crypt.verify(password_insert, password):              #method to verify is the inputed password match with the password in the database with the specified username
                logging.info('password matched')
                db.close()
                gc.collect()
                session['logged_in'] = True                                    #creating a session for the user after logging_in
                session['username'] = request.form['username']
                flash('You were successfully logged in')
                return redirect(url_for('Dashboard', username=username))
            else:
                logging.info('wrong credentials')
                error = 'wrong credentials'
                return render_template('login.html', error=error)
        else:
            error = 'No user'
            logging.info('no user')
            return render_template('login.html', error=error)
    else:
        error = 'wrong method'
        logging.info('wrong method')
        return render_template('login.html', error=error)

@app.route('/Logout')
def Logout():
   session.pop('logged_in', None)                                            #clearing the username in the session if there
   flash('You were successfully logged out')
   return redirect(url_for('Login'))
            
             
if __name__ == '__main__':
   app.run( debug = True )
