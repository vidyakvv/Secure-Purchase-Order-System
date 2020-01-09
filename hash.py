import hashlib
import sqlite3

#Storing hashed password in database 

hashObject = hashlib.sha3_224()
username = input("enter the username :")
password = input("password :")
conn = sqlite3.connect('database.db')
cur = conn.cursor()

hashObject.update(password.encode("utf8"))
digest = hashObject.digest()
cur.execute("UPDATE users SET password=? WHERE username=?", (digest,username))
conn.commit()

conn.close()