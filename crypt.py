import threading
from threading import Thread
import Crypto
from Crypto.PublicKey import RSA
import ast
import socket
import sys
import errno
import cPickle
from socket import error as socket_error
import os
import base64
from Crypto.Cipher import AES
from subprocess import call
import platform

CONNECTED= False
BLOCK_SIZE=16
PADDING='{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
IP = 0.0.0.0#socket.gethostbyname(socket.gethostname())


def get_lan_ip():
  ip = socket.gethostbyname(socket.gethostname())
  return ip


def clear_screen():
  plat=platform.system()
  if plat=='Windows':
    os.system('cls')
  else:
    os.system('clear')


def kill():
  call(['cmd','/c','taskkill','/f','-IM','python.exe'])  

def listener(sock,  cipher):
  try:
    msg_len = int(sock.recv(10))
    ciphertext = sock.recv(msg_len)
    msg = DecodeAES(cipher, ciphertext)
    if msg=='QUIT':
      sock.send('')
    print(msg)#+'\nLocalhost: '
    listener(sock, cipher)
  except:
    1+1
  sys.exit()    


def messenger(sock, cipher):
  msg = raw_input()
  if msg=='\n' or msg=='':
    messenger(sock, cipher)
  elif msg=='QUIT':
    sock.send('')
    kill()
  else:
    msg='    ' + msg
    ciphertext = EncodeAES(cipher, msg)
    sock.send(str(len(ciphertext)))
    sock.send(ciphertext)
    messenger(sock, cipher)
  
  sys.exit()     

  
def key_exchange_client(sock):
  RSAkey = new_keypair()
  public = RSAkey.publickey()
  sock.send(str(len(cPickle.dumps(public))))  #send the length of the key
  sock.send(cPickle.dumps(public))
  msg_len = int(sock.recv(10))
  msg = sock.recv(msg_len)
  msg = cPickle.loads(msg)
  secret = RSAkey.decrypt(ast.literal_eval(str(msg)))
  cipher=AES.new(secret)
  print '\n'
  #while 1:
  global CONNECTED
  CONNECTED=True
  clear_screen()
  print "Enter QUIT to exit\n"
  t1=Thread(target=messenger, args=(sock, cipher,))
  t2=Thread(target=listener, args=(sock, cipher))
  try:
    t1.start()
    t2.start()
    
  except:
    print 'error'


def new_keypair():
  print 'Generating Keypair...'
  return RSA.generate(2048)
    
  
def key_exchange_server(connection, client):
  print 'Recieving Keys...'
  key_len = int(connection.recv(5))
  key = connection.recv(key_len)
  key = cPickle.loads(key) 
  secret=os.urandom(16)  #AES secret
  cipher=AES.new(secret)
  msg_out = cPickle.dumps(key.encrypt(secret, 32))
  connection.send( str( len(msg_out) ) )
  connection.send(msg_out)
  clear_screen()
  print "Enter QUIT to exit\n"
  global CONNECTED
  CONNECTED=True
  t1=Thread(target=messenger, args=(connection, cipher,))
  t2=Thread(target=listener, args=(connection, cipher))
  try:
    t1.start()
    t2.start()
  except:
    print 'error'



def connect(ip_addr):
  print 'Connecting to ' + ip_addr +' ...'
  sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  addr=(ip_addr, 430)
  failstate=False
  
  try:
    sock.connect(addr)
  except socket_error as serr:
    if serr.errno == 10061:
      print '\nConnection Refused\n'
    else:
      print '\nSocket Error\n'
    main()

  print 'Connection Successful'
  key_exchange_client(sock) 
  

def listen():
  print 'listening for an incoming connection...'
  sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  #addr=('10.0.0.13', 430)  # add method to get localhost
  
  addr=(IP, 430)  #attempt
  try:    
    sock.bind(addr)
  except:
    print '\nError while binding the socket'
    print 'Set bind address with the setip command\n'
    main()
  sock.listen(1)
  connection, client = sock.accept()
  print 'Connection Recieved'
  key_exchange_server(connection, client)  


def ping(ip):
  try:
    if platform.system()=='Windows':
      call(['cmd', '/c', 'ping', ip])
    else:
      call(['/bin/bash', 'ping', ip])
    print ''
  except:
    print 'Error'

def print_usage(cmd):
  if cmd=='connect':
    print 'usage - connect <ip>'

  else:
    print 'cmd not found: ' + cmd +'\n'
  print ''

def print_help():
  print ''
  print 'help -- display commands'
  print 'listen -- listen for incoming connection'
  print 'connect <host ip> -- connect to host <host ip>'
  print 'ping <ip> -- ping target <ip>'
  print 'ip -- show current lan ip'
  print 'setip <ip> -- set ip to listen on'
  print 'quit -- exit program'
  print ''


def set_ip(addr):
  global IP
  IP = addr

def main():
  quit=False
  while not quit and not CONNECTED:
    cmd=raw_input('Crypt$:')
    if cmd=='quit' or cmd=='exit':
      quit=True
    
    elif cmd=='help':
      print_help()
    
    elif cmd=='listen':
      listen()

    elif cmd=='connect':
      print_usage('connect')

    elif cmd=='ip':
      print IP
    
    elif len(cmd.split(' '))>1:
      if cmd.split(' ')[0]=='connect':
        ip=cmd.split(' ')[1]
        connect(ip)
      elif cmd.split(' ')[0]=='ping':
        ip=cmd.split(' ')[1]
        ping(ip)
      elif cmd.split(' ')[0]=='setip':
        set_ip(cmd.split(' ')[1]) 
      else:
        print 'command not found: ' + cmd[0]+'\n'
        print_help()
    
    else:
      print 'command not found: ' + cmd + '\n'
      print_help()


try:
  main()
except:
  print 'error'  
