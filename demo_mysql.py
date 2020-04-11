#from app import app
import mysql.connector

db = mysql.connector.connect(user='root', password='OriafoDikodin1',
                              host='127.0.0.1',
                              )
mycursor = db.cursor()


#mycursor.execute("CREATE DATABASE abraham")
mycursor.execute("USE abraham")
#mycursor.execute("drop table log_details")
mycursor.execute("CREATE TABLE log_details (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255), email VARCHAR(50))")
#sql = "INSERT INTO log_details (username, password) VALUES (%s, %s)"
#val = ("John", "123456")
#mycursor.execute(sql, val)
#mycursor.execute("alter table log_details modify email VARCHAR(50)")
db.commit()