#!/usr/bin/python

#Date: 2017-11-16
#Description: Simple TCP client

import socket
target_host = "0.0.0.0"
target_port = 9999

#create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#connect the client
client.connect((target_host,target_port))

#send some data
client.send("ABCDEF\n")

#receive some data
response = client.recv(4096)

print(response)
