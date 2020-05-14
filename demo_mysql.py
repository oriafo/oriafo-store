#from app import app
import mysql.connector

db = mysql.connector.connect(user='root', password='OriafoDikodin1',
                              host='127.0.0.1',
                              )
mycursor = db.cursor()

#mycursor.execute("CREATE DATABASE abraham")
mycursor.execute("USE abraham")
#mycursor.execute("drop table log_details")
mycursor.execute("CREATE TABLE log_details (id INT AUTO_INCREMENT PRIMARY KEY NOT NULL, ids INT(255) NOT NULL, username VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, email VARCHAR(50) NOT NULL)")
#mycursor.execute("CREATE TABLE auth_table (id INT  UNSIGNED  AUTO_INCREMENT NOT NULL, username VARCHAR(255) NOT NULL,  token VARCHAR(255) NOT NULL, expires datetime, PRIMARY KEY (id))")
#mycursor.execute("CREATE TABLE log_details (id INT  UNSIGNED  AUTO_INCREMENT NOT NULL,token VARCHAR(255) NOT NULL, expires datetime, PRIMARY KEY (id))")
#sql = "INSERT INTO log_details (username, password) VALUES (%s, %s)"
#val = ("John", "123456")
#mycursor.execute(sql, val)
#mycursor.execute("alter table log_details modify email VARCHAR(50)")
db.commit()