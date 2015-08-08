from Crypto.Cipher import AES as aes
from Crypto import Random as rand
from Crypto.Random.random import sample
from Crypto.Hash import HMAC as hmac
from Crypto.Hash import SHA256 as sha
# Steps of generating keys.
# Let Dkey be the key obtained with diffie hellman key exchange method.
# Let's say that aes key and hmac key 


# CFB Mode encryption
# For encryption and decryption, same aes object must not be used. Create aec object for each encryption and decryption.
# To use CBC mode, we need to come up with a padding scheme because this mode takes the input string with size multiple of 16 bytes.
class aes_encryption:
	def __init__(self, key = '', mode = '', bytes = 32, hmac_key = ''):
		self.key = key
		self.mode = mode
		self.bytes = bytes
		self.hmac_key = hmac_key

	def extract_keys(self, entropy):
		#Extact 32 bytes byte string. Divide into 16 and 16 bytes for hmac and aes key.
		h = sha.new()
		h.update(entropy)
		extracted = h.hexdigest()
		return extracted[:32], extracted[32:]

	def makeKey(self, bytes):
		# 16 or 32 bytes are allowed.
		# Generate bytes + bytes bytes keys for hmac and aes.
		population = 'abcdefghijklmnopqrstuwxyz'
		population = population + population.upper() + '/><!@#$%^&*()~+-`'
		aeskey = sample(population, bytes)
		aeskey = ''.join(aeskey)
		hmackey = sample(population, bytes)
		hmackey = ''.join(hmackey)
		return aeskey, hmackey

	def enc(self, message, key, hmackey):
		# make random initial vector with aes.block_size and then instantiate aes.
		iv = rand.new().read(aes.block_size) # 16 bytes for initial vector.
		encryption = aes.new(key, aes.MODE_CFB, iv)

		# hmac the message.
		h = hmac.new(hmackey)
		h.update(message)
		mac = h.digest()

		# encrypted format will be 16bytes iv + encrypted message + hmac size.
		# hmac size is 16 bytes by default because the dafault digestmode is md5 and it returns 128 bits(16 bytes) size of binary string.
		# So the final encrypted message size is 16 + size(message) + 16.
		encrypted = iv + encryption.encrypt(message) + mac
		return encrypted

	def dec(self, cipher, key, hmackey):
		# Extract iv, MAC from the ciphertext.
		size_iv = 16
		size_cipher = len(cipher)
		size_msg = size_cipher - 16 - 16 # total length - size of iv - size of hmac.
		iv = cipher[:size_iv] # The end index 16 is exclusive. So iv = 'initial vector', size = 14, and iv[:6] = 'initia'
		

		msg = cipher[16:16+size_msg]
		# make aes object for decryption.
		decryption = aes.new(key, aes.MODE_CFB, iv)

		# decrypt
		decrypted = decryption.decrypt(msg)
		
		# Authenticate the message by checking MAC.
		mac_cipher = cipher[16+size_msg : ]
		h = hmac.new(hmackey)
		h.update(decrypted)
		mac = h.digest()
		if mac == mac_cipher :
			return decrypted
		else : 
			return None