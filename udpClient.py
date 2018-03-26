#!/usr/bin/python

#Date: 2017-11-16
#Description: Simple UDP client

import socket
target_host = "127.0.0.1"
target_port = 80

#create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#send some data
client.sendto("AAABBBCCC",(target_host,target_port))

#receive some data
data, addr = client.recvfrom(4096)

print data
