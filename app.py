from flask import Flask, redirect, render_template, g, url_for, request, session, flash, url_for, logging, make_response
#from wtforms import Form, BooleanField, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
from datetime import timedelta
from functools import wraps
import mysql.connector
import logging
import gc
                                                                            #pip freeze > requirements.txt
  
app = Flask(__name__)                                                           #creating an instance of the app
app.secret_key = 'my first app'                                                 #secret key required by session
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)
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
@app.route('/Home')
def Home():
   return render_template('home.html')

                                                                                #setting a cookie
@app.route('/cookie/')
def cookie():
    if not request.cookies.get('foo'):
        res = make_response("Setting a cookie")
        res.set_cookie('foo', 'bar', max_age=60*60*24*365*2)
    else:
        res = make_response("Value of cookie foo is {}".format(request.cookies.get('foo')))
    return res

                                                                                #deleting a cookie
@app.route('/delete-cookie/')
def delete_cookie():
    res = make_response("Cookie Removed")
    res.set_cookie('foo', 'bar', max_age=0)
    return res
                                                                                #about-us route

@app.route('/article/', methods=['POST', 'GET'])
def article():
    if request.method == 'POST':
        print(request.form)
        res = make_response("")
        res.set_cookie("font", request.form.get('font'), 60*60*24*15)
        res.headers['location'] = url_for('article')
        return res, 302
    
    return render_template('article.html')

@app.route('/visits-counter/')
def visits():
    if 'visits' in session:
        session['visits'] = session.get('visits') + 1  # reading and updating session data
    else:
        session['visits'] = 1 # setting session data
    return "Total visits: {}".format(session.get('visits'))
 
@app.route('/delete-visits/')
def delete_visits():
    session.pop('visits', None) # delete visits
    return 'Visits deleted'


@app.route('/session/')
def updating_session():
    res = str(session.items())
 
    cart_item = {'pineapples': '10', 'apples': '20', 'mangoes': '30'}
    if 'cart_item' in session:
        session['cart_item']['pineapples'] = '100'
        session.modified = True
    else:
        session['cart_item'] = cart_item
 
    return res


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
            mycursor.execute('SELECT * FROM log_details WHERE username = %s OR password = %s', (username, password,))
            data = mycursor.fetchone()
            print(data)
            #mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username]) #selecting "username" from the table "log_details" 
            #data = mycursor.fetchone()                                              #fecting the first row of the output result in case of multi-rows
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
    if 'username' in request.cookies == request.form["username"]:
        username = request.cookies.get('username')
        password = request.cookies.get('password')
        print(username)
        print(password)
        db = mysql.connector.connect(**config)
        mycursor = db.cursor()
        mycursor.execute("USE abraham")
        mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username])   
        data = mycursor.fetchone()
        print(data)
        #print(password)
        if data and sha256_crypt.verify(password, data[2]):
            print(username + ' ' + password)
            session['logged_in'] = True 
            session['username'] = data[1]
            print(session['username'])
            mycursor.close()
            return redirect(url_for('Dashboard'))
        else:
            return redirect(url_for('Login'))
    elif request.method == 'POST':
            error = None
            global remember
            username = request.form["username"]
            print(username)
            password_insert = request.form["password"]
            print(password_insert)
            remember = request.form.getlist('Remember_me')
            db = mysql.connector.connect(**config)
            mycursor = db.cursor()
            mycursor.execute("USE abraham")
            mycursor.execute("SELECT * FROM log_details WHERE username = %s", [username])   
            data = mycursor.fetchone()
            print(data) 
            if data != None:
                #print(data)                                                        #logic to determine if the username is in the database
                password = data[2]
                if sha256_crypt.verify(password_insert, password):              #method to verify is the inputed password match with the password in the database with the specified username
                    logging.info('password matched')
                    db.close()
                    gc.collect()
                    session['logged_in'] = True                                    #creating a session for the user after logging_in
                    session['username'] = request.form['username']
                    flash('You were successfully logged in')
                    if remember:
                        resp = make_response(redirect('/Dashboard'))
                        resp.set_cookie('username', data[1], max_age=60*60*24*366)
                        resp.set_cookie('password', password, max_age=60*60*24*366)
                        resp.set_cookie('remember', 'checked', max_age=60*60*24*366)
                        return resp
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
   session.pop('username', None)
   flash('You were successfully logged out')
   return redirect(url_for('Login'))
            
             
if __name__ == '__main__':
   app.run( debug = True )
