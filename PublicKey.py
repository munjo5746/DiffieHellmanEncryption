from Crypto.Util.number import getPrime as gp, isPrime as isp, bytes_to_long as btl,long_to_bytes as ltb, inverse as inv, getRandomRange as randrange
import random
#import Crypto.Random.random as rand
import time

#prime = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
#gen = 2

# A multiplicative group order p under mod p is a cyclic.

# Find the generator of a multiplicative group order 'prime'.
# check http://math.stackexchange.com/questions/23832/example-for-cyclic-groups-and-selecting-a-generator
# For some g in the group, if g**((p-1)/2)%p == -1 == p-1, then g is generator.

# NOTE
# Sending message through diffie hellman key, the message 'm' must be in the cyclic group
# in order to decipher the correct 'm'. It can be done by breaking m into small part so that each part
# is less than the prime. Then, deciphering each part and combine. But here, we just take m < prime
# for simplicity.
class diffie_hellman:
	def __init__(self):
		self.generator = 2
		self.prime = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		self.exp = random.randint(2,200) # exp == a where g**a%p 

	def extract(self, key, gab, prime):
		inverse_key = inv(gab, prime)
		message = key*inverse_key%prime
		return ltb(message)

	def long_to_byte(self, l):
		return ltb(l)
	
	def byte_to_long(self, b):
		return btl(b)

	def genKey(self, bytes):
		# make p = 2*q+1
		p = 0
		q = 0
		while not isp(p):
			q = gp(bytes)
			p = 2*q+1
		
		# Find generator.
		# Find g such that g**((p-1)/2) = -1 = p-1 mod p
		g = 0
		candidate = 2
			#print candidate
		while True:
			if (randrange(2, p)**((p-1)/2)%p) == p-1:
				g = candidate
				break;
		# for e in xrange(2, p):
		# 	if self.fast_mod(e, (p-1)/2, p) == p-1:
		# 		g = e
		# 		break
		self.prime = p
		self.generator = g
		self.exp = random.randint(0,p/2)

#	refer http://people.reed.edu/~jerry/361/lectures/bigprimes.pdf
	def fast_mod(self, base, exp, mod):
		result = 1
		while exp > 0:
			if exp%mod == 0:
				result = result
				base = base**2%mod
				exp = exp/2
			else:
				result = result*base%mod
				base = base
				exp = exp-1
		return result
