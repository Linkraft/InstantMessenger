# Coded by Jordan Smith for Computer & Information Security, Fall 2019
# Sources used:
# https://docs.python.org/3/howto/sockets.html
# https://pymotw.com/2/select/

import socket, sys, select, random, signal

def main():
    argv = sys.argv
    length = len(argv)
    HOSTNAME = ''
    PORTNUM = 9999
    if (length > 1 and argv[1] == "-s"):
        if (length > 2 and argv[2].isnumeric()):
            PORTNUM = int(argv[2])
        serverSide(PORTNUM)
    elif (length > 1 and argv[1] == "-c"):
        if (length > 2 and argv[2]):
            HOSTNAME = argv[2]
            if (length > 3 and argv[3].isnumeric()):
                PORTNUM = int(argv[3])
            clientSide(HOSTNAME, PORTNUM)

def serverSide(PORTNUM):
    # Create the nonblocking TCP/IP socket
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the serverSock to the port
    server_address = ('localhost', PORTNUM)
    print("Server running on port {}".format(PORTNUM))
    serverSock.bind(server_address)

    # Listen for the client to connect
    serverSock.listen()

    clientSock, client_address = serverSock.accept()
    print('Connected to', client_address)
    # clientSock.setblocking(0)

    incoming = [ serverSock ]
    outgoing = [ clientSock ]

    while incoming:
        readSocks, writeSocks, exceptSocks = select.select(incoming, outgoing, incoming)
        # Check all readable sockets for network activity
        for sock in readSocks:
            # The socket with network activity is the server
            if sock is serverSock:
                if clientSock not in incoming:
                    incoming.append(clientSock)
            # The socket with network activity is the client
            else:
                data = sock.recv(1024)
                if data:
                    print(data)
                    # Now we can mark the client as ready for our response
                    if sock not in outgoing:
                        outgoing.append(sock)
        


def clientSide(HOSTNAME, PORTNUM):
    # Create the nonblocking TCP/IP socket
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the client socket to the server's exposed port
    server_address = (HOSTNAME, PORTNUM)
    print("Client connecting to host '{}' on port {}".format(HOSTNAME, PORTNUM))
    clientSock.connect(server_address)

    incoming = [ clientSock, sys.stdin ]
    outgoing = [ clientSock, sys.stdout ]

    while incoming:
        readSocks, writeSocks, exceptSocks = select.select(incoming, outgoing, incoming)
        data = ''
        for sock in readSocks:
            data = sock.recv(1024)
        for sock in writeSocks:
            sock.sendall(data)                

if __name__ == "__main__":
    main()