from flask import Flask, redirect, render_template, g, url_for, request, session, flash, url_for, logging, make_response, jsonify
from passlib.hash import argon2
import datetime  
import uuid
import jwt
import uuid
from functools import wraps
import mysql.connector
import logging
import gc
                                                                            #pip freeze > requirements.txt
  
app = Flask(__name__)                                                           #creating an instance of the app
app.config['SECRET_KEY'] = 'my first app'                                                 #secret key required by session
#app.config['PERMANENT_SESSION_LIFETIME'] =  datetime.timedelta(days=366)
logging.basicConfig(level=logging.INFO)
#app.config['SESSION_COOKIE_SECURE'] = True                                 #unable for production
app.config['session.modified'] = True



global COOKIE_TIME_OUT
COOKIE_TIME_OUT = 60*60*24*366 


                                                                                #config MYSQL
config = {
    'user': 'root',
    'password': 'OriafoDikodin1',
    'host': '127.0.0.1',
    'database': 'abraham',
}



                                                                                #home route
@app.route('/Home')
def Home():
    return render_template('home.html')

                                                                                #setting a cookie
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
        password = argon2.using(rounds=4).hash(request.form["password"])
        comfirm = request.form["comfirm password"]
        if argon2.verify(comfirm, password):
            db = mysql.connector.connect(**config)                                  #connecting to mysql database
            mycursor = db.cursor()                                                  #creating cursor object
            mycursor.execute("USE abraham")
            mycursor.execute('SELECT * FROM log_details WHERE username = %s OR password = %s', (username, password,))
            data = mycursor.fetchone()
            print(data)
            if data != None:   
                logging.info('invalid credentials')
                error = 'invalid credentials'
                return render_template('register.html', error=error)                #logic to determine if the username exist in the database before so as to eliminate the case of having two similar username in the database
            else:
                ids = print(uuid.uuid4())
                mycursor.execute("INSERT INTO log_details (ids, username, password, email) VALUES (%s, %s, %s, %s)",(ids, username, password, email))       
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
    
@app.route('/login', methods=['POST'])
@logout_required 
def login():
    if request.method == 'POST':
        username_a = request.form["username"]
        username = username_a.strip()
        password_b = request.form["password"]
        password_insert = password_b.strip()
        remember = request.form.getlist('Remember_me')
        db = mysql.connector.connect(**config)
        mycursor = db.cursor()
        mycursor.execute("USE abraham")
        mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username])   
        data = mycursor.fetchone() 
        if data != None:                                                       #logic to determine if the username is in the database
            password = data[2]
            if argon2.verify(password_insert, password):
                logging.info('password matched')
                db.close()
                gc.collect()
                session['logged_in'] = True                                    #creating a session for the user after logging_in
                session['username'] = username
                flash('You were successfully logged in')
                if remember:
                    tokin = jwt.encode({'user' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=31622400)}, app.config['SECRET_KEY'])
                    print(tokin)
                    resp = make_response(redirect('/Dashboard'))
                    resp.set_cookie('y2k', value=tokin, max_age=COOKIE_TIME_OUT, path='/',httponly=True, samesite='Strict')    # secure=True you must use this for production
                    db = mysql.connector.connect(**config)
                    mycursor = db.cursor()
                    mycursor.execute("USE abraham")
                    #sql = "INSERT INTO auth_table (token) VALUES (%s)"
                    mycursor.execute("INSERT INTO auth_table (username,token) VALUES (%s, %s)", (username, tokin)) 
                    #val = (tokin)
                    #mycursor.execute(sql, val)
                    db.commit()
                    db.close()
                    gc.collect()
                    print(session)
                    return resp
                return redirect('/Dashboard')
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
@login_required
def Logout():
   session.pop('logged_in', None)                                            #clearing the username in the session if there
   session.pop('username', None)
   flash('You were successfully logged out')
   return redirect(url_for('Login'))
            
             
if __name__ == '__main__':
   app.run( debug = True )
