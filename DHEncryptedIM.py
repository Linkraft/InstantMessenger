# Original author: Henry Tan
# Modified by Kevin Butler

import os
import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import random

from collections import deque
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC
from Cryptodome.Cipher import AES

from collections import deque

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
logger = logging.getLogger('main')
###########


def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-confkey', dest='confkey', metavar='CONFIDENTIALITY KEY', type=str,
    help = 'Key used in encryption')
  parser.add_argument('-authkey', dest='authkey', metavar='AUTHENTICITY KEY', type=str,
    help = 'Key with which HMAC is computed')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

def init(crypt):
  global s
  args = parse_arguments()

  logging.basicConfig()
  logger.setLevel(logging.CRITICAL)
  
  #Catch the kill signal to close the socket gracefully
  signal.signal(signal.SIGINT, sigint_handler)

  if args.connect is None and args.server is False:
    print_how_to()
    quit()

  if args.connect is not None and args.server is not False:
    print_how_to()
    quit() 

  if args.confkey is None or args.authkey is None:
    print_how_to()
    quit()

  #hash keys and take first 128 bits (=16 bytes)
  args.authkey=SHA256.new(args.authkey).digest()[0:16]
  crypt['authout']=HMAC.new(args.authkey, digestmod=SHA256)
  crypt['authin']=HMAC.new(args.authkey, digestmod=SHA256)
  args.confkey=SHA256.new(args.confkey).digest()[0:16]

  if args.connect is not None:
    iv=os.urandom(32)
    crypt['confout']=AES.new(args.confkey, AES.MODE_CBC, iv[:16])
    crypt['confin']=AES.new(args.confkey, AES.MODE_CBC, iv[16:])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))
    s.send(iv)

  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) #Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))
    iv=s.recv(32)
    crypt['confout']=AES.new(args.confkey, AES.MODE_CBC, iv[16:])
    crypt['confin']=AES.new(args.confkey, AES.MODE_CBC, iv[:16])

def numto16bytestr(num):
  # Converts int to 16-byte string with a bunch of 0s in front of it
  # Obviously 16 bytes is unnecessarily large, but: simplicity.
  num = str(num)
  return (16-len(num))*'0' + num

def padstrto16bytes(data):
  # Ensures string ends in newline, and pads to next multiple of 16 bytes
  return data + (-len(data)%16)*'x'

def encodemessage(data,crypt):
  data = numto16bytestr(len(data))+padstrto16bytes(data)
  crypt['authout'].update(data)
  data = data + crypt['authout'].digest()[:32]
  data = crypt['confout'].encrypt(data)
  return data

def decodemessage(data,crypt):
  data = crypt['confin'].decrypt(data)
  mac = data[-32:]
  data = data[:-32]
  crypt['authin'].update(data)
  if mac != crypt['authin'].digest():
    exit("AUTH FAIL on: " + data)
  data = data[16:16+int(data[:16])]
  return data

def main():
  global s
  datalen=64
  
  crypt={}
  init(crypt)
  
  inputs = [sys.stdin, s]
  outputs = [s]

  output_buffer = deque()

  while s is not None: 
    # Prevents select from returning the writeable socket when there's nothing to write
    if (len(output_buffer) > 0):
      outputs = [s]
    else:
      outputs = []

    readable, writeable, exceptional = select.select(inputs, outputs, inputs)

    if s in readable:
      data = s.recv(datalen)

      if ((data is not None) and (len(data) > 0)):
        data = decodemessage(data, crypt)
        sys.stdout.write(data) #  Assuming that stdout is always writeable
      else:
        # Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        for datapiece in [data[i:i+datalen-48] for i in range(0,len(data),datalen-48)]:
          datapiece = encodemessage(datapiece, crypt)
          output_buffer.append(datapiece)
      else:
        # EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()
        bytesSent = s.send(data)
        # If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None

if __name__ == "__main__":
  main()
