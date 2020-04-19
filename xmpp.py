#!/usr/bin/python

import base64
import hashlib
import hmac
import itertools

charset = "_abcdefghijklmnopqrstuvwxyz"

initial_message = "n=?,r=?"
server_first_message = "r=?,s=?,i=?"
server_final_message_compare = "v=?"
r = server_first_message[2:server_first_message.find('s=')-1]
s = server_first_message[server_first_message.find('s=')+2:server_first_message.find('i=')-1]
i = server_first_message[server_first_message.find('i=')+2:]

for passwordlen in range(1,3):
	for k in itertools.permutations(charset, passwordlen):
		password = "?" + "".join(k)
		salt = base64.b64decode(s)
		client_final_message_bare = 'c=?,r=' + r
		salt_password = hashlib.pbkdf2_hmac('sha1', password, salt, int(i))
		auth_message = initial_message + ',' + server_first_message + ',' + client_final_message_bare
		server_key = hmac.new(salt_password, 'Server Key', hashlib.sha1).digest()
		server_signature = hmac.new(server_key, auth_message, hashlib.sha1).digest()
		server_final_message = 'v=' + base64.b64encode(server_signature)
		if server_final_message == server_final_message_compare:
			print "password : " + password
			h = hashlib.new('sha1')
			h.update(password)
			print "flag sha1 : " + h.hexdigest()
			exit(-1)
