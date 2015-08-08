# Testing our AES encryption and Diffiel Hellman Public key exchange.
from PublicKey import diffie_hellman
from AES_Encryption import aes_encryption
#import random
#from Crypto.Util.number import getPrime as gp, isPrime as isp, bytes_to_long as btl,long_to_bytes as ltb, inverse as inv, getRandomRange as randrange

#from AES_Encryption import aes_encryption

prime = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
gen = 2

client1 = diffie_hellman() # a is in [2,49]
client2 = diffie_hellman()# b is in [50,99]

# client1.prime = prime
# client2.prime = prime
# client1.generator = gen
# client2.generator = gen
# client1.exp = random.randint(2,200)
# client2.exp = random.randint(2,200)


# client1 make g^a * message == entropy and sent it to client2.
# First these two clients exchange g^a and g^b to calculate g^ab.
# Then, one of the client (client1) send enc = message * g^ab for AES enctyption.
# Then, client2 decipher enc * (g^ab)^-1 = message * g^ab * (g^ab)^-1 = message * 1 = message.
entropy = 'entropy'
g_a = client1.generator**client1.exp%client1.prime # g^a and send it
g_b = client2.generator**client2.exp%client2.prime # g^b and send it

# client1 gets g^b from client2 and caculate g^ab.
# And then make enc = message * g^ab and send it to client2.
g_ab = g_b**client1.exp%client1.prime
enc = g_ab * client1.byte_to_long(entropy)

# client2 decipher enc.
# use extract() function.
decipher = client2.extract(enc, g_ab, client2.prime)

if entropy == decipher:
	pass
else:
	print 'Not match!\n'
	print 'entropy is ', entropy, '\ndecipher is ', decipher


# Extract the key for hamac and aes for enctyption.
encrypt = aes_encryption()
hmackey, aeskey = encrypt.extract_keys(entropy)
encrypt.key = aeskey
encrypt.hmac_key = hmackey

# encrypt message.
message = 'This message will be encrypted by the first client! And decrypted by the second client!'
print 'Encrypt message : ', message, '\n'
encrypted_msg = encrypt.enc(message, encrypt.key, encrypt.hmac_key)

# extract key for decryption.
decrypt = aes_encryption()
hmackey, aeskey = decrypt.extract_keys(entropy)
decrypt.key = aeskey
decrypt.hmackey = hmackey

decrypted_msg = decrypt.dec(encrypted_msg, decrypt.key, decrypt.hmackey)
print 'Decrypt message : ', decrypted_msg, '\n'
