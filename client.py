import socket
from AES_Encryption import aes_encryption as aes
from PublicKey import diffie_hellman as pb
import sys, select

def communicate(lst, encrypt):

	# lst = [sys.stdin, client]
	while 1:
		read, write, err = select.select(lst, [], [])
		for e in read:
			if e == lst[1]:
				# read message.
				data = e.recv(2048)
				if data:
					# Decrypt and print message
					print '[Received] ', encrypt.dec(data, encrypt.key, encrypt.hmac_key)
					print '[Encrypted Message] ', data
					print '==================================================================='
			else:
				msg = sys.stdin.readline()
				print '[Send] ', msg 
				# Encrypt and send the message.
				msg = encrypt.enc(msg, encrypt.key, encrypt.hmac_key)
				print '[Encrypted Message] ', msg
				lst[1].send(msg)
				print '==================================================================='



# Pass arg as 'entropy' and then exponent.
# The second client only pass the exponent.

# Based on the number of arguments, we decide if the client is connecting 
# or receiving.
# program.py 'connect' or 'establish' localhost port

#client
# addr = 'localhost'
# port = 8000
if len(sys.argv) < 3:
	# Error
	print 'Not enough arguments.'
	sys.exit()
else:
	role = sys.argv[1] # connect or establish
	addr = sys.argv[2]
	port = int(sys.argv[3])


# Decide the role of client.
# The connecting client must send the publick key to the server side client.
if role == 'connect':
	print 'connecting\n'
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((addr, port))
	
	# We need to exchange the key.
	# First send g^a
	pb_key = pb()
	key = pb_key.generator**pb_key.exp % pb_key.prime
	client.send(str(key)) # send it.

	# We wait for entropy that is sent along with g^ab.
	lst = [sys.stdin, client]
	entropy = 'entropy'
	g_b = None
	complete = False
	while not complete:
		# Need to get g^b, and send the entropy.
		try:
			data = client.recv(2048)
			if g_b is None and data:
				# This means that we got g^b
				g_b = int(data)

				# make g^ab * entropy
				entropy_temp = g_b * key * pb_key.byte_to_long(entropy) % pb_key.prime
				client.send(str(entropy_temp))
				complete = True
				
		except:
			continue
			
	# ready to establish the communication.
	encrypt = aes()
	encrypt.key, encrypt.hmac_key = encrypt.extract_keys(entropy)
	print 'Communication Established!!'
	communicate(lst, encrypt)

if role == 'establish':
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((addr, port))
	server.listen(1)
	c, a = server.accept()
	print 'client addr : ', a, ' is connected!'
	lst = [sys.stdin, c]

	# key exchanging
	exchanged = False
	g_a = None
	pb_key = pb()
	g_b = pb_key.generator ** pb_key.exp % pb_key.prime
	encrypt = aes()
	entropy = None
	while not exchanged:
		try:
			data = c.recv(2048) # try to get g^a
			if data:
				if g_a is None:
					g_a = int(data)
					c.send(str(g_b))
				else:
					# This means that we got the entropy.
					entropy = pb_key.extract(int(data), g_a * g_b % pb_key.prime, pb_key.prime)
					encrypt.key, encrypt.hmac_key = encrypt.extract_keys(entropy)
					exchanged = True

		except:
			continue
	if entropy is None:
		print 'Communication is not established!!'
	print 'Communication Established!!'
	communicate(lst, encrypt)
