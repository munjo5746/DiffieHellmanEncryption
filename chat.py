import socket
import select
import sys



# hostname and port number will be obtained from the command line.
# Server side code.
# addr = 'localhost'
# port = 8000
addr = sys.argv[1]
port = int(sys.argv[2])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((addr, port))
server.listen(2)
clients = []

print 'server waiting for the first client.'
# Accept the first client.
client, addr = server.accept()
print 'client addr : ', addr, 'connected!'
clients.append(client)

print 'server waiting for the second client.'
# Accept the second client.
client, addr = server.accept()
print 'client addr : ', addr, 'connected!'
clients.append(client)

# Now ready to exchange key.
# The server receives g^a and the entropy string from the first client.
# And then, the server sends them to the second client.
while 1:
	readable, writable, err = select.select(clients, [], [])
	for c in readable:
		try:
			data = c.recv(2048)
			if data:
				for i in clients:
					if i != c:
						i.send(data)
			else:
				c.close()
		except:
			continue

server.close()
#while 1:
#	readable, writable = select.select(clients, clients, [])
