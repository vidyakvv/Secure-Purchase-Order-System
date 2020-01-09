from flask import Flask
from flask import render_template
from flask import request
import sqlite3
from flask import abort
import random
import sys
from flask import session
import socket
import hashlib
import rsa 
import sys
import time


app = Flask(__name__)
app.secret_key = '123'
size = 4098
supervisorId = 'vidya'
supervisorIp = '127.0.0.1:9090'
purDeptid = 'rachu'
purDeptip = '127.0.0.1:8080'

#reading private key of user
f = open("prvUser.txt", "rb")
privateKeyUser1 = f.read()
privateKeyUser = rsa.PrivateKey.load_pkcs1(privateKeyUser1)
f.close()

#reading public key of KDC
f = open("pubKDC.txt", "rb")
pubkeyKDC1 = f.read()
pubkeyKDC = rsa.PublicKey.load_pkcs1(pubkeyKDC1)
f.close()

#Login page
@app.route('/')
def hello_world():
	return render_template('login.html')

#Logout page
@app.route('/logout')
def logout():
   # remove the username from the session if it is there
	session.clear()
	return render_template('login.html')

#Validation of the user
@app.route('/page', methods = ['POST','GET'])
def role():
	#checking if user is already logged in	
	try:
		session['user'] = request.form['username']
		pwd = request.form['password']
		#hashing the password and comparing it with the value in database
		pwd = hashFile(pwd)
	except KeyError as e:
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	print("user name = ", session['user'])

	#connect to database 
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM users WHERE username=? AND password=?",(session['user'],pwd,))
	rows = cur.fetchall()
	if rows == []:
		print("hash value of password not matching or username not valid")
		abort(500, 'Invalid login credentials')
	role  = rows[0][2]
	print(role)	

	#displaying web pages based on roles
	if role == 'user':
		return render_template('page.html',msg="Welcome "+ session['user'])
	elif role == 'supervisor':
		cur.execute("SELECT * FROM supervisor WHERE orderstatus=?",('CREATED',))
		rows = cur.fetchall()
		return render_template('supervisor.html', rows = rows)
	elif role == 'purchase':
		cur.execute("SELECT * FROM orders WHERE status=?",('PROCESSING',))
		rows = cur.fetchall()
		return render_template('purchase.html', rows=rows)
	connectionClose(conn)

#Display user page
@app.route('/orderCreate')
def orderCreation():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)
	return  render_template('orderCreate.html',user=session['user'])

#User creating the PO
@app.route('/result', methods = ["POST",'GET'])
def result():
	
	#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)		
	
	#Open database connection
	conn = connectionOpen()
	cur = conn.cursor()
	print("user name result= ", session['user'])
	numberOfItems = request.form['numberofitems']
	creditcardNumber = request.form['creditcard']
	ordernumber = random.randint(1,10000)
	session['orderNumber'] = str(ordernumber)
	#Insert PO in database
	cur.execute("INSERT INTO orders (order_number, username, status, numberofitems, creditcard, ipAddress) VALUES (?, ?, ?,?,?,?)", (ordernumber, session['user'], "CREATED", 				   		int(numberOfItems),creditcardNumber,"127.0.0.1:5000"))
	conn.commit()
	msg = 'Order number: ' + str(ordernumber) + ' is created sucessfully'
	return  render_template('requestKeys.html',msg = msg)

#Requesting Keys of Supervisor and purchase department by user
#from Centralized Authority
@app.route('/requestKeys', methods = ["POST",'GET'])
def reQuestKeys():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#connect to KDC
	sock = KDCConnect()
	#Requesting Supervisor public Key
	requestSupervisor = "idfrom=" + session['user'] + " idTo="  + supervisorId + " ipTo=" + supervisorIp + " timestamp="+ str(time.time()) + " role=" + "supervisor"
	requestSupervisor = requestSupervisor.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestSupervisor, pubkeyKDC)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for supervisor public key to Central Authority. Exiting"
		abort(500, msg)

	# Receive Public of Supervisor from CA or KDC
	datarecv = sock.recv(size)
	session['pubKeySuper'] = datarecv
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of supervisor")
		
	sock.close()
	
	#Requesting Purchase Department's key
	print("request purchase dept's public key")
	#Connect to KDC
	sock1 = KDCConnect()
	#Requesting Purchase Dept's public Key
	requestPurchase = "idfrom=" + session['user'] + " idTo="  + purDeptid + " ipTo=" + purDeptip + " timestamp="+ str(time.time()) + " role=" + "purdept"
	requestPurchase = requestPurchase.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestPurchase, pubkeyKDC)
	datasent = sock1.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for purchase dept: public key to Central Authority. Exiting"
		abort(500, msg)

	#Receive Purchase Dept's public key
	datarecv = sock1.recv(size)
	session['pubKeyPurchase'] = datarecv

	if sys.getsizeof(datarecv) > 0:
		print("public key of purchase department recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of purchase department")
		abort(500,"error in receiving public key of purchase department")
		sock1.close()
		
	sock1.close()
	msg = "Supervisor's public key and purchase department's public key has been sucessfully received from the central authority"
	return  render_template('sendOrder.html',msg = msg)

#Send Order to Supervisor and Purchase Department
@app.route('/sendOrder', methods = ["POST",'GET'])
def sendOrder():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#Get public key of supervisor and purchase dept
	conn = connectionOpen()
	cur = conn.cursor()
	orderDetails = "order=" + session['orderNumber']  + " user=" + session['user'] + " status=" + "CREATED"
	pubKeySupervisor = rsa.PublicKey.load_pkcs1(session['pubKeySuper'])
	pubKeyPurchase = rsa.PublicKey.load_pkcs1(session['pubKeyPurchase'])

	#Encrypt PO
	#Create signature
	orderDetailsEncryptSupervisor = rsa.encrypt(orderDetails.encode('utf8'),pubKeySupervisor)
	orderDetailsEncryptpurchase = rsa.encrypt(orderDetails.encode('utf8'),pubKeyPurchase)
	signatureUser = rsa.sign(orderDetails.encode('utf8'), privateKeyUser, 'SHA-224')
	print(orderDetailsEncryptSupervisor)

	#Insert PO in Supervisor's and Purchase Dept's database
	cur.execute("UPDATE orders SET signature_client = ? WHERE order_number=?", (str(signatureUser),session['orderNumber']))
	conn.commit()

	#cur.execute("INSERT INTO supervisor (order, encryptedData, signatureUser) VALUES (?,?,?)", ("order1", orderDetailsEncryptSupervisor, signatureUser))
	orderLabel = session['orderNumber']
	cur.execute("INSERT INTO supervisor (orderLabel,encryptedData,signatureUser,orderstatus) VALUES (?, ?, ?,?)", (orderLabel, orderDetailsEncryptSupervisor, signatureUser,"CREATED"))
	cur.execute("INSERT INTO purchasedepartment (orderLabel,encryptedData,signatureUser,orderstatus) VALUES (?,?,?,?)", (orderLabel, orderDetailsEncryptpurchase,signatureUser,"CREATED"))
	conn.commit()
	
	msg = "Order details and signature sucessfully sent to Supervisor and Purchase department"
	return  render_template('orderEnd.html',msg = msg)

#Supervisor approval	
@app.route('/supervisorApproval', methods = ["POST",'GET'])
def supervisorApproval():

	#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#Get order details for approval
	orderNumber = request.form['order']
	session["orderNumberSuper"] = orderNumber
	print("order number is ", orderNumber)
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM supervisor WHERE orderLabel=?",(orderNumber,))
	rows = cur.fetchall()
		
	encryptedData = rows[0][1]
	signatureUser = rows[0][2]
	
	privateKeySupervisor = pvtKeySup()

	#Decrypt PO using private key
	decryptedData = rsa.decrypt(encryptedData, privateKeySupervisor)
	decryptedDatastr = decryptedData.decode('utf8')
	session['decrypteddOrderSuper'] = decryptedData
	order, user, status = decryptedDatastr.split(' ')
	_,order = order.split('=')
	_,user = user.split('=')
	_,status = status.split('=')

	cur.execute("SELECT * FROM orders WHERE order_number=?",(order,))
	rowsOrder = cur.fetchall()
	ipAddressUser = rowsOrder[0][6]

	#request for user's public key to decrypt signature
	sock = KDCConnect()
	requestUser = "idfrom=" + session['user'] + " idTo="  + user + " ipTo=" + ipAddressUser + " timestamp="+ str(time.time()) + " role=" + "user"
	requestUser = requestUser.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestUser, pubkeyKDC)
	print(requestMsgCipher)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for user's public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock.recv(size)
	pubKeyUser = rsa.PublicKey.load_pkcs1(datarecv)
	
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of user")
		
	sock.close()

	#User's signature verification by supervisor
	if rsa.verify(decryptedData, signatureUser, pubKeyUser):
		signMsg = "signature verification of user done sucessfully"
		cur.execute("UPDATE supervisor SET orderstatus = ? where orderLabel=?", ("PROCESSING",order))
		conn.commit()
		
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("PROCESSING",order))
		orderStatusmsg = "PROCESSING"
		conn.commit()
		return render_template('keyPurchaseDept.html',signMsg = signMsg, orderStatusmsg=orderStatusmsg)
		
	else:
		signMsg = "signature verification has failed. Order is rejected automatically"
		orderStatusmsg = "REJECTED"
		cur.execute("UPDATE supervisor SET orderstatus = ? where orderLabel=?", ("REJECTED",order))
		conn.commit()
		cur.execute("SELECT * FROM orders WHERE order_number=?",(orderNumber,))
		rows = cur.fetchall()

		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",order))
		conn.commit()
		abort(404, "Order Rejected due to signature verification failure")

#Request sent to CA for purchase department's public key by supervisor 
@app.route('/PurchaseDeptKey', methods=["POST",'GET'])
def purchaseDeptKey():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	print("request purchase dept's public key")
	#Connect to CA
	sock1 = KDCConnect()
	requestPurchase = "idfrom=" + session['user'] + " idTo="  + purDeptid + " ipTo=" + purDeptip + " timestamp="+ str(time.time()) + " role=" + "purdept"
	requestPurchase = requestPurchase.encode('utf8')
	#Sending request
	requestMsgCipher = encrypt_RSA(requestPurchase, pubkeyKDC)
	datasent = sock1.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for purchase dept: public key to Central Authority. Exiting"
		abort(500, msg)
	#Receive public key of purchase department
	datarecv = sock1.recv(size)
	session['pubKeyPurchase'] = datarecv

	if sys.getsizeof(datarecv) > 0:
		print("public key of purchase department recieved sucessfully from Central Authority")
		return render_template("sendOrderFromSupToPur.html", msg = "Public Key sucessfully received from Central Authority. Send order to purchase dept ?")
	else:
		print("error in receiving public key of purchase department")
		abort(500,"error in receiving public key of purchase department")
		sock1.close()	

#Send order to purchase department from Supervisor
@app.route('/PurchaseDeptSend', methods=["POST",'GET'])
def sendOrderToPurchaseFromoSupervisor():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#Retrieve PO and encrypt using public key of Purchase dept
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM supervisor WHERE orderLabel=?",(session["orderNumberSuper"],))
	rows = cur.fetchall()
	encryptedOrder = rows[0][1]
	pubKeyPurchase = rsa.PublicKey.load_pkcs1(session['pubKeyPurchase'])
	encryptOrderToPurchase = rsa.encrypt(session['decrypteddOrderSuper'],pubKeyPurchase)
	
	#reading pvt key
	privateKeySupervisor = pvtKeySup()
	#signature of supervisor
	signatureSupervisor = rsa.sign(session['decrypteddOrderSuper'], privateKeySupervisor, 'SHA-224')

	#write in purchase departments table
	cur.execute("UPDATE purchasedepartment SET signatureSuper=?, encryptedDataSuper=?,orderstatus=? WHERE orderLabel=?", (signatureSupervisor, encryptOrderToPurchase,"PROCESSING",session['orderNumberSuper']))
	conn.commit()
	
	return render_template("supervisorend.html", msg= "Order sucessfully sent to purchase department")

#Purchase department is decrypting the PO sent from User and Supervisor 
@app.route('/purchaseVerify', methods=['POST','GET'])
def purchaseVerify():
	#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#Retrieve PO from database
	session['orderNumPurchase'] = request.form['order']
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM purchasedepartment WHERE orderLabel=?",(session["orderNumPurchase"],))
	rows = cur.fetchall()
	encryptedDataUser = rows[0][1]
	session['signatureUser'] = rows[0][2]
	session['signatureSuper'] = rows[0][3]
	encryptedDataSuper = rows[0][5]
	
	#Decrypt User's PO as well as supervisor's PO  
	privateKeyPurDept = pvtKeyPur()
	session['decryptDataUser'] = rsa.decrypt(encryptedDataUser, privateKeyPurDept)
	session['decryptDataSupervisor'] = rsa.decrypt(encryptedDataSuper, privateKeyPurDept)

	return render_template('purchaseOrderVerify.html')

#Comparing Hash digest from supervisor and User(PO not tampered) 
@app.route('/purchasehashVerify', methods=["POST",'GET'])
def orderhashVerfiy():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	hashUser = hashFile(session['decryptDataUser'].decode('utf8'))
	hashSuper = hashFile(session['decryptDataSupervisor'].decode('utf8'))

	if hashUser == hashSuper:
		msg = "Hash Values Matching. Messages have not been tampered."
		return render_template("signatureVerify.html", msg=msg)
	else:	
		msg = "Hash Value Not MAtch. Rejecting the order"
		conn = connectionOpen()
		cur = conn.cursor()
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",session['orderNumPurchase']))
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? WHERE orderLabel=?", ("REJECTED",session['orderNumPurchase']))
		conn.commit()
		abort(500, msg)

#Decrypting Signatures and verification
@app.route('/signaturehVerify', methods=['POST','GET'])
def signatureVerification():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	#requesting keys for user and supervisor
	order, user, status = session['decryptDataUser'].decode('utf8').split(' ')
	_,order = order.split('=')
	_,user = user.split('=')
	_,status = status.split('=')
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM orders WHERE order_number=?",(order,))
	rowsOrder = cur.fetchall()
	ipAddressUser = rowsOrder[0][6]

	#Connect to KDC
	sock = KDCConnect()
	requestUser = "idfrom=" + session['user'] + " idTo="  + user + " ipTo=" + ipAddressUser + " timestamp="+ str(time.time()) + " role=" + "user"
	requestUser = requestUser.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestUser, pubkeyKDC)
	print(requestMsgCipher)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for user's public key to Central Authority. Exiting"
		abort(500, msg)
	#Receive public key of Supervisor
	datarecv = sock.recv(size)
	pubKeyUser = rsa.PublicKey.load_pkcs1(datarecv)
	
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of user")
		
	sock.close()
	
	#Verify User's signature
	verifyUser = rsa.verify(session['decryptDataUser'], session['signatureUser'], pubKeyUser)
	print("Verification User " , verifyUser)


	#Requesting Supervisor Key
	sock = KDCConnect()
	requestSupervisor = "idfrom=" + session['user'] + " idTo="  + supervisorId + " ipTo=" + supervisorIp + " timestamp="+ str(time.time()) + " role=" + "supervisor"
	requestSupervisor = requestSupervisor.encode('utf8')
	#Encrypt and send request for Supervisor's public key
	requestMsgCipher = encrypt_RSA(requestSupervisor, pubkeyKDC)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for supervisor public key to Central Authority. Exiting"
		abort(500, msg)

	#Receive public key of supervisor from CA
	datarecv = sock.recv(size)
	pubKeySuper = rsa.PublicKey.load_pkcs1(datarecv)
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of supervisor")
		
	sock.close()

	#Verify Supervisor's PO
	verifySuper = rsa.verify(session['decryptDataSupervisor'], session['signatureSuper'], pubKeySuper)
	print("Verification Super " , verifySuper)
	
	if verifySuper == 'SHA-224' and verifyUser == 'SHA-224':
		msg = "Sucessfully verified signatures"
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? where orderLabel=?", ("APPROVED",order))
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("APPROVED",order))
		conn.commit()
		return render_template("purchaseend.html", msg= msg, approved = "APPROVED")
	else:	
		if verifySuper != "SHA-224":
			msg = "Supervisor Signature Verification Failed"
		else:
			msg = "User Signature Verification Failed"
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? where orderLabel=?", ("REJECTED",order))
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",order))
		conn.commit()
		abort(500,msg)
###############################################################################

# Required functions
#Read Supervisor's private key from file
def pvtKeySup():
	f = open("pvtsup.txt", "rb")
	privateKeySupervisor1 = f.read()
	privateKeySupervisor = rsa.PrivateKey.load_pkcs1(privateKeySupervisor1)
	f.close()	
	return	privateKeySupervisor

#Read Purchase Department's private key from file
def pvtKeyPur():
	f = open("prvpurDept.txt", "rb")
	privateKeyPurDept1 = f.read()
	privateKeyPurDept = rsa.PrivateKey.load_pkcs1(privateKeyPurDept1)
	f.close()
	return privateKeyPurDept


#View Order Status for the user
@app.route('/viewOrderStatus')
def viewOrderStatus():
		#checking if user is logged in	
	if not session.get('user') :
		msg= 'Invalid login!!!!!!'
		return render_template('login.html', msg=msg)

	print("view status function")
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM orders where username=?", (session['user'],))
	rows = cur.fetchall() 
	connectionClose(conn)
	return  render_template('viewOrderStatus.html',user=session['user'], rows= rows)

#Database connection open
def connectionOpen():
	conn = sqlite3.connect('database.db')
	return conn

#Database connection close
def connectionClose(conn):
	conn.close()
	return

#Sending order details to the supervisor by user
def sendOrderToSupervisor(sock, message):

	sendMsg = sock.send(message)
	if sys.getsizeof(sendMsg)>0:
		print("data sucessfully sent to supervisor")
	else:
		print("data was not sent to supervisor")
		exit()

	msgFromSupervisor = sock.recv(size)
	if sys.getsizeof(msgFromSupervisor)>0:
		print("data sucessfully received from supervisor")
	else:
		print("data was not received from supervisor")
		exit()
	print("response from supervisor ", str(msgFromSupervisor)) 
	print("Recieved data from supervisor")
	return msgFromSupervisor

def sendOrderToPurDept(sock, message):
	sendMsg = sock.send(message)
	if sys.getsizeof(sendMsg)>0:
		print("data sucessfully sent to purchase dept")
	else:
		print("data was not sent to purchase dept")
		exit()

	msgFromPurDept = sock.recv(size)
	if sys.getsizeof(msgFromPurDept)>0:
		print("data sucessfully received from purchase dept")
	else:
		print("data was not received from purchase dept")
		exit()
	print("response from purchase dept: ", str(msgFromPurDept)) 
	return msgFromPurDept

#Connect to Supervisor
def supervisorConnect():
	supervisorIp = '127.0.0.1'
	supervisorPort = 9090
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((supervisorIp, supervisorPort))
	return s

#Connect to KDC
def KDCConnect():
	KDCIp = '127.0.0.1'
	KDCPort = 5055
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((KDCIp, KDCPort))
	return s

#connect to Purchase Department
def purDeptConnect():
	purDeptIp = '127.0.0.1'
	putDeptPort = 8080
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((purDeptIp, putDeptPort))
	return s
		

#Encrypting file using RSA
def encrypt_RSA(message, public_key):
	cipher = rsa.encrypt(message, public_key)
	return cipher

#Decryption using RSA
def decrypt_RSA(cipher_text, private_key):
	message = rsa.decrypt(cipher_text, private_key)
	return message

#Generating RSA keys
def generateRSAKeys():
	public_key, private_key = rsa.newkeys(512)

#Requesting public key of supervisor from CA
def requestPublicKeyFromCA(role):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	CA_ip = '127.0.0.1'
	CA_port = '7070'
	s.connect(CA_ip, CA_port)
	s.send("Request for public key of ", role)
	pub_key = s.recv(1024)
	return pub_key

#hashing the file
def hashFile(orderDetails):
	hashObject = hashlib.sha3_224()
	#Converting string to a byte objeect
	hashObject.update(orderDetails.encode("utf8"))
	digest = hashObject.digest()
	return digest

if __name__ == '__main__':
    app.run(use_reloader=True, debug=True)

