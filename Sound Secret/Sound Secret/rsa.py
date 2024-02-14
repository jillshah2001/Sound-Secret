from crypto.PublicKey import RSA
from crypto import Random

def newkeys(keysize):
   random_generator = Random.new().read
   key = RSA.generate(keysize, random_generator)
   private, public = key, key.publickey()
   return public, private

public, private = newkeys(2048)
f = open('public.pem', 'wb')
f.write(public.exportKey('PEM'))
f.close()
print('Public Key Generated...')
f = open('private.pem', 'wb')
f.write(private.exportKey('PEM'))
f.close()
print('Private Key Generated...')