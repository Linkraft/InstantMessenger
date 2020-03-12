# Modified by Jordan Smith for CIS4360, Fall 2019
# Original author: Henry Tan

import os
import sys
import argparse
import socket
import select
import logging
import signal # To kill the programs nicely
import random
from collections import deque

# Required libraries for encryption
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
logger = logging.getLogger('main')
###########

def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  serverOrClient = parser.add_mutually_exclusive_group()
  serverOrClient.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  serverOrClient.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int,
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')
  parser.add_argument('-confkey', dest='confkey', metavar='CONFKEY', type=str, required=True,
    help = 'Confidentiality key used for encryption')
  parser.add_argument('-authkey', dest='authkey', metavar='AUTHKEY', type=str, required=True,
    help = 'Authenticity key used to computer the HMAC')

  return parser.parse_args()

def print_how_to():
  print("This program must be run with exactly ONE of the following options")
  print("-c [HOSTNAME] <PORTNUM> [-CONFKEY] [-AUTHKEY]")
  print("-s            <PORTNUM> [-CONFKEY] [-AUTHKEY]")

def sigint_handler(signal, frame):
  logger.debug("SIGINT Captured! Killing")
  global s, server_s
  if s is not None:
    s.shutdown(socket.SHUT_RDWR)
    s.close()
  if server_s is not None:
    s.close()

  quit()

def init():
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

  # Get the confkey and authkey from argparse
  global confkey, authkey
  confkey = args.confkey
  authkey = args.authkey

  # Hash the keys in SHA-256, storing only the first 128 bits
  confSHA = SHA256.new()
  authSHA = SHA256.new()
  confSHA.update(confkey)
  authSHA.update(authkey)
  confkey = confSHA.digest()
  authkey = authSHA.digest()
  confkey = confkey[:16]
  authkey = authkey[:16]
    
  if args.connect is not None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Connecting to ' + args.connect + ' ' + str(args.port))
    s.connect((args.connect, args.port))

  if args.server is not False:
    global server_s
    server_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_s.bind(('', args.port))
    server_s.listen(1) # Only one connection at a time
    s, remote_addr = server_s.accept()
    server_s.close()
    logger.debug("Connection received from " + str(remote_addr))

def main():
  global s
  
  init()
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
      IV = s.recv(16)          # 16 since AES-128 is 16 bytes
      lengthDigits = s.recv(1)
      num = int(lengthDigits)
      numZeroes = s.recv(num)  # 1 or 2 depending on number of digits in numZeroes
      msg = s.recv(1024)       # Max buffer size is 1024
      theirHMAC = s.recv(256)  # SHA-256

      # Decrypt the message for possible printing
      AEScipher = AES.new(confkey, AES.MODE_CBC, IV)    
      data = AEScipher.decrypt(msg)
      data = data[int(numZeroes):]

      # Now reconstruct the HMAC from the IV and msg and do an authentication check
      myHMAC = HMAC.new(authkey, digestmod=SHA256)
      myHMAC.update(msg)
      if(myHMAC.digest() != theirHMAC):
        print("Error! HMAC authentication failed!")
        quit()

      # Print the data if the authentication check passes
      if ((data is not None) and (len(data) > 0)):
        sys.stdout.write(data) # Assuming that stdout is always writeable
      else:
        # Socket was closed remotely
        s.close()
        s = None

    if sys.stdin in readable:
      data = sys.stdin.readline(1024)
      if(len(data) > 0):
        output_buffer.append(data)
      else:
        # EOF encountered, close if the local socket output buffer is empty.
        if( len(output_buffer) == 0):
          s.shutdown(socket.SHUT_RDWR)
          s.close()
          s = None

    if s in writeable:
      if (len(output_buffer) > 0):
        data = output_buffer.popleft()

        # Start encryption process
        # Make a fresh IV
        IV = Random.new().read(AES.block_size)

        # Create an AES cipher in CBC mode that uses the confkey and the IV
        AEScipher = AES.new(confkey, AES.MODE_CBC, IV)

        # AES requires the message length must be a multiple of 16, so pad with 0's to fulfill this requirement
        lengthDigits = 1
        numZeroes = 16 - (len(data) % 16)
        if (numZeroes >= 10):
          lengthDigits = 2
        data = ('0' * numZeroes) + data 
        msg = AEScipher.encrypt(data)

        # Send the IV, the number of zeroes added, and the message
        s.send(IV)
        s.send(str(lengthDigits))
        s.send(str(numZeroes))
        bytesSent = s.send(msg)

        # Now send raw bytes of HMAC of encrypted message for authentication purposes
        myHMAC = HMAC.new(authkey, digestmod=SHA256)
        myHMAC.update(msg)
        s.send(myHMAC.digest())

        # If not all the characters were sent, put the unsent characters back in the buffer
        if(bytesSent < len(data)):
          output_buffer.appendleft(data[bytesSent:])

    if s in exceptional:
      s.shutdown(socket.SHUT_RDWR)
      s.close()
      s = None


if __name__ == "__main__":
  main()
