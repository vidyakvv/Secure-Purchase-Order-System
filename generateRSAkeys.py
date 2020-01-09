# RSA Key generation program. Keys are generated and stored in files.
#For each entity keys are generated separately

import rsa
(pubkey, pvtkey) = rsa.newkeys(1024)
#Saving public key and private key in PEM format
exppub =pubkey.save_pkcs1(format='PEM')
exppriv = pvtkey.save_pkcs1(format='PEM')
#Save in respective files
f1 = open("pubpurDept.txt", "wb")
f2 = open("prvpurDept.txt","wb")
f1.write(exppub)
f2.write(exppriv)
f1.close()
f2.close()
