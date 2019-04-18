# -*- coding: utf-8 -*-
# ! python v.2.7.14
import os
import random
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from datetime import timedelta

# "constants" - program flow and execution defined variables
J = 2
K = 3
R = 3
W = 4

# globals
valid_clients_data = []  # List of Client objects
clients_data_mutex = threading.Lock()
printing_mutex = threading.Lock()
debug_mode = False
server_data = None  # Server object
sockets = None


class Server:
    def __init__(self):
        self.name = None
        self.mac_address = None


class Client:
    def __init__(self):
        self.name = None
        self.state = "DISCONNECTED"
        self.random_num = random.randint(0, 999999)
        self.mac_address = None
        self.udp_port = None
        self.ip_address = None
        self.consecutive_non_received_alives = 0
        self.is_alive_received = False
        self.is_data_received = False
        self.is_end_data_received = False
        self.data_received_timeout_exceeded = False
        self.conf_tcp_socket = None


class Sockets:
    def __init__(self):
        self.udp_socket = None
        self.udp_port = None

        self.tcp_socket = None
        self.tcp_port = None


def manage_command_line_input():
    try:
        while True:
            command = read_from_stdin()
            if command == "quit":
                os.kill(os.getpid(), signal.SIGINT)
            elif command == "list":
                list_accepted_clients()
            else:
                print_message("ERROR -> " + command + " is not an accepted command")
                print_accepted_commands()
    except (KeyboardInterrupt, SystemExit):
        return


def list_accepted_clients():
    if valid_clients_data:
        printing_mutex.acquire()
        clients_data_mutex.acquire()
        print("  NAME |      IP      |      MAC      | RAND NUM |     STATE     ")
        print("-------|--------------|---------------|----------|---------------")
        for client in valid_clients_data:
            print(" " + client.name + " | " + str(13 * " " if client.ip_address is None else
                  client.ip_address + " " * (13 - len(client.ip_address))) + "| " +
                  client.mac_address + "  | " + str(format(client.random_num, "06")) + "   | " +
                  client.state + "")

        print  # simply prints new line
        sys.stdout.flush()
        printing_mutex.release()
        clients_data_mutex.release()


def print_accepted_commands():
    print_message("INFO  -> Accepted commands are:\n" +
                  "\t\t    quit -> finishes server\n" +
                  "\t\t    list -> lists allowed clients")


def read_from_stdin():
    line = sys.stdin.readline()
    return line.split("\n")[0]


def parse_argv(argv):
    software_config_file = None
    allowed_clients_file = None
    for i in range(len(argv)):
        if argv[i] == "-d":
            global debug_mode
            debug_mode = True
            print_message("INFO  -> Debug mode enabled (-d)")
        elif argv[i] == "-c" and len(argv) > i + 1:
            try:
                software_config_file = open(argv[i + 1], 'r')
            except IOError:
                print_message("ERROR -> Can't open file named: " + argv[i + 1] +
                              ". Will open server.cfg (default config. file)")
        elif argv[i] == "-u" and len(argv) > i + 1:
            try:
                allowed_clients_file = open(argv[i + 1], 'r')
            except IOError:
                print_message("ERROR -> Can't open file named: " + argv[i + 1]
                              + ". Will open equips.dat (default allowed clients file)")
    if debug_mode:
        print_message("DEBUG -> Read command line input")

    if software_config_file is None:
        try:
            software_config_file = open("server.cfg", 'r')
        except IOError:
            print_message("ERROR -> Can't open default file ./client.cfg")
            exit(1)

    if allowed_clients_file is None:
        try:
            allowed_clients_file = open("equips.dat", 'r')
        except IOError:
            print_message("ERROR -> Can't open default file ./equips.dat")
            exit(1)
    parse_and_save_software_config_file_data(software_config_file)
    parse_and_save_allowed_clients_file_data(allowed_clients_file)
    if debug_mode:
        print_message("DEBUG -> Read data from configuration files")


def parse_and_save_software_config_file_data(software_config_file):
    global server_data
    global sockets
    server_data = Server()
    sockets = Sockets()

    for line in software_config_file:
        if line != "\n":
            attribute, value = line.split("\n")[0].split(" ")
            if attribute == "Nom":
                server_data.name = value
            elif attribute == "MAC":
                server_data.mac_address = value
            elif attribute == "UDP-port":
                sockets.udp_port = int(value)
            elif attribute == "TCP-port":
                sockets.tcp_port = int(value)

    software_config_file.close()


def parse_and_save_allowed_clients_file_data(allowed_clients_file):
    global valid_clients_data
    num_clients = 0
    for line in allowed_clients_file:
        if line != "\n":
            client = Client()
            client_name, client_mac = line.split("\n")[0].split(" ")
            client.name = client_name
            client.mac_address = client_mac
            valid_clients_data.append(client)
            num_clients += 1

    allowed_clients_file.close()
    if debug_mode:
        print_message("DEBUG -> Read " + str(num_clients) + " allowed clients' data")


def print_message(to_print):
    printing_mutex.acquire()
    current_time = time.strftime("%H:%M:%S", time.localtime(time.time()))
    print(str(current_time) + " - " + to_print)
    sys.stdout.flush()
    printing_mutex.release()


def setup_udp_socket():
    global sockets
    sockets.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockets.udp_socket.bind(("", sockets.udp_port))


def setup_tcp_socket():
    global sockets
    sockets.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockets.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sockets.tcp_socket.bind(("", sockets.tcp_port))
    sockets.tcp_socket.listen(5)


def service():
    """
    initiates udp and tcp service loops:
    creates a thread (daemon) to initiate tcp loop
    and then initiates udp service loop
    """
    thread_for_tcp = threading.Thread(target=tcp_service_loop)
    thread_for_tcp.daemon = True
    thread_for_tcp.start()

    udp_service_loop()


def udp_service_loop():
    """
    Waits for udp connection,
    when getting connection creates a thread (daemon) to serve it and
    keeps waiting for incoming connections on udp socket
    """
    if debug_mode:
        print_message("DEBUG -> UDP socket enabled")

    while True:
        received_package_unpacked, client_ip_address, client_udp_port = \
            receive_package_via_udp_from_client(78)

        thread_to_serve_udp_connection = threading.Thread(target=serve_udp_connection,
                                                          args=(received_package_unpacked,
                                                                client_ip_address,
                                                                client_udp_port))
        thread_to_serve_udp_connection.daemon = True
        thread_to_serve_udp_connection.start()


def receive_package_via_udp_from_client(bytes_to_receive):
    received_package_packed, (client_ip_address, client_udp_port) = sockets.udp_socket.\
                                                                    recvfrom(bytes_to_receive)
    received_package_unpacked = struct.unpack('B7s13s7s50s', received_package_packed)
    package_type = received_package_unpacked[0]
    client_name = received_package_unpacked[1].split("\x00")[0]
    client_mac_address = received_package_unpacked[2].split("\x00")[0]
    random_num = received_package_unpacked[3].split("\x00")[0]
    data = received_package_unpacked[4].split("\x00")[0]

    if debug_mode:
        print_message("DEBUG -> \t\t Received " + get_packet_string_from_type(package_type) +
                      "; \n" + "\t\t\t\t\t  Bytes: " + str(bytes_to_receive) + ", \n" +
                      "\t\t\t\t\t  name: " + client_name + ", \n" +
                      "\t\t\t\t\t  mac: " + client_mac_address + ", \n" +
                      "\t\t\t\t\t  rand num: " + random_num + ", \n" +
                      "\t\t\t\t\t  data: " + data + "\n")
    return received_package_unpacked, client_ip_address, client_udp_port


def get_packet_string_from_type(integer):
    # signup packet types
    if integer == 0x00:
        return "REGISTER_REQ"
    elif integer == 0x01:
        return "REGISTER_ACK"
    elif integer == 0x02:
        return "REGISTER_NACK"
    elif integer == 0x03:
        return "REGISTER_REJ"
    # keep in touch packet types
    elif integer == 0x10:
        return "ALIVE_INF"
    elif integer == 0x11:
        return "ALIVE_ACK"
    elif integer == 0x12:
        return "ALIVE_NACK"
    elif integer == 0x13:
        return "ALIVE_REJ"
    # send configuration packet types
    elif integer == 0x20:
        return "SEND_FILE"
    elif integer == 0x21:
        return "SEND_ACK"
    elif integer == 0x22:
        return "SEND_NACK"
    elif integer == 0x23:
        return "SEND_REJ"
    elif integer == 0x24:
        return "SEND_DATA"
    elif integer == 0x25:
        return "SEND_END"
    # get configuration packet types
    elif integer == 0x30:
        return "GET_FILE"
    elif integer == 0x31:
        return "GET_ACK"
    elif integer == 0x32:
        return "GET_NACK"
    elif integer == 0x33:
        return "GET_REJ"
    elif integer == 0x34:
        return "GET_DATA"
    elif integer == 0x35:
        return "GET_END"
    # error
    else:
        return "ERROR"


def get_packet_type_from_string(string):
    # signup packet types
    if string == "REGISTER_REQ":
        return 0x00
    elif string == "REGISTER_ACK":
        return 0x01
    elif string == "REGISTER_NACK":
        return 0x02
    elif string == "REGISTER_REJ":
        return 0x03
    # keep in touch packet types
    elif string == "ALIVE_INF":
        return 0x10
    elif string == "ALIVE_ACK":
        return 0x11
    elif string == "ALIVE_NACK":
        return 0x12
    elif string == "ALIVE_REJ":
        return 0x13
    # send configuration packet types
    elif string == "SEND_FILE":
        return 0x20
    elif string == "SEND_ACK":
        return 0x21
    elif string == "SEND_NACK":
        return 0x22
    elif string == "SEND_REJ":
        return 0x23
    elif string == "SEND_DATA":
        return 0x24
    elif string == "SEND_END":
        return 0x25
    # get configuration packet types
    elif string == "GET_FILE":
        return 0x30
    elif string == "GET_ACK":
        return 0x31
    elif string == "GET_NACK":
        return 0x32
    elif string == "GET_REJ":
        return 0x33
    elif string == "GET_DATA":
        return 0x34
    elif string == "GET_END":
        return 0x35
    # error
    else:
        return 0x09


def tcp_service_loop():
    """
    Waits for tcp connection,
    when getting connection creates a thread to serve it and
    keeps waiting for incoming connections on tcp socket
    """
    if debug_mode:
        print_message("DEBUG -> TCP socket enabled")

    while True:
        new_socket, (ip_address, port) = sockets.tcp_socket.accept()
        received_package_unpacked = receive_package_via_tcp_from_client(new_socket, 178)
        # create thread to serve tcp connection
        thread_to_serve_tcp_connection = threading.Thread(target=serve_tcp_connection,
                                                          args=(received_package_unpacked,
                                                                new_socket, ip_address))
        thread_to_serve_tcp_connection.daemon = True
        thread_to_serve_tcp_connection.start()


def serve_tcp_connection(received_package_unpacked, socket, client_ip_address):

    package_type = received_package_unpacked[0]

    if package_type == get_packet_type_from_string("SEND_FILE"):
        serve_send_file(received_package_unpacked, client_ip_address, socket)
    elif package_type == get_packet_type_from_string("GET_FILE"):
        serve_get_file(received_package_unpacked, client_ip_address, socket)


def receive_package_via_tcp_from_client(socket, bytes_to_receive):
    received_package_packed = socket.recv(bytes_to_receive)
    received_package_unpacked = struct.unpack('B7s13s7s150s', received_package_packed)
    package_type = received_package_unpacked[0]
    client_name = received_package_unpacked[1].split("\x00")[0]
    client_mac_address = received_package_unpacked[2].split("\x00")[0]
    random_num = received_package_unpacked[3].split("\x00")[0]
    data = received_package_unpacked[4].split("\x00")[0]

    if debug_mode:
        print_message("DEBUG -> \t\t Received " + get_packet_string_from_type(package_type) +
                      "; \n" + "\t\t\t\t\t  Bytes: " + str(bytes_to_receive) + ", \n" +
                      "\t\t\t\t\t  name: " + client_name + ", \n" +
                      "\t\t\t\t\t  mac: " + client_mac_address + ", \n" +
                      "\t\t\t\t\t  rand num: " + random_num + ", \n" +
                      "\t\t\t\t\t  data: " + data + "\n")
    return received_package_unpacked


def serve_send_file(received_package_unpacked, client_ip_address, socket):
    """
    This method is executed when receiving a SEND_FILE package on tcp socket.
    It processes the END_FILE package received and if everything goes correctly
    creates a thread to keep track of received send_data packages timeout which
    will execute function keep_in_touch_send_data, and finally calls
    save_send_data_packages function.

    :param received_package_unpacked: send_file received pdu
    :param client_ip_address: ip address of client that sent received_package_unpacked
    :param socket: socket where received_package_unpacked was received and which will
    be used for further communication with client
    """
    try:
        client_name = received_package_unpacked[1].split("\x00")[0]
        client_mac_address = received_package_unpacked[2].split("\x00")[0]
        client_random_num = int(received_package_unpacked[3].split("\x00")[0])
        client = get_client_from_name(client_name)

        clients_data_mutex.acquire()
        if not are_name_and_mac_valid(client_name, client_mac_address) or client.state == \
                "DISCONNECTED":
            if debug_mode:
                print_message(
                    "DEBUG -> Declined SEND_FILE request. Client:" + client_name + ", ip:" +
                    client_ip_address + ", mac:" + client_mac_address + str(" (not allowed)" if not
                    are_name_and_mac_valid(client_name, client_mac_address)
                    else " (not registered)"))

            send_rej = construct_send_rej_package("not allowed" if not
            are_name_and_mac_valid(client_name, client_mac_address) else "not registered")
            clients_data_mutex.release()
            send_package_via_tcp_to_client(send_rej, socket)
            socket.close()
            return

        elif not are_random_num_and_ip_address_valid(client_name, client_random_num,
                                                     client_ip_address) or \
                client.conf_tcp_socket is not None:
            if debug_mode and client.conf_tcp_socket is None:
                print_message("DEBUG -> Error in received SEND_FILE. Client:" + client_name
                              + " ip:" + client_ip_address + ", mac:" + client_mac_address +
                              ", rand_num:" + str(client_random_num) + " (Registered as: " +
                              client.name + ", ip:" + client.ip_address + ", mac:" +
                              client.mac_address + ", rand_num:" + str(client.random_num) + ")")

            if client.conf_tcp_socket is not None:
                print_message(
                    "INFO -> There already is an operation on configuration file going on. "
                    "Client:" + client_name + " ip:" + client_ip_address +
                    ", mac:" + client_mac_address + ", rand_num:" +
                    str(client_random_num) + " (Registered as: " + client.name + ", ip:" +
                    client.ip_address + ", mac:" + client.mac_address +
                    ", rand_num:" + str(client.random_num) + ")")
                clients_data_mutex.release()
                send_nack = construct_send_nack_package("existant operation already going on")
            else:
                clients_data_mutex.release()
                send_nack = construct_send_nack_package("wrong data received")

            send_package_via_tcp_to_client(send_nack, socket)
            socket.close()
            return

        else:  # everything correct
            client.conf_tcp_socket = socket
            clients_data_mutex.release()
            print_message("INFO  -> Accepted configuration file sending request. Client: " +
                           client_name + ", ip: " + client_ip_address + ", mac: " +
                          ", random num: " + str(client_random_num))
            send_ack = construct_send_ack_package(client.name, client.random_num)
            send_package_via_tcp_to_client(send_ack, socket)
            to_write = open(client.name + ".cfg", "w+")  # creates file
            # thread to keep track of received send_data packages timeout
            thread_for_send_data = threading.Thread(target=keep_in_touch_send_data,
                                                    args=(client, datetime.now() +
                                                          timedelta(seconds=W)))
            thread_for_send_data.daemon = True
            thread_for_send_data.start()
            save_send_data_packages(socket, to_write, client)
            to_write.close()
            socket.close()
            clients_data_mutex.acquire()
            client.conf_tcp_socket = None
            clients_data_mutex.release()
    # datetime.now() is None when main thread exits, so could throw AttributeError
    except AttributeError:
        return


def serve_get_file(received_package_unpacked, client_ip_address, socket):
    """
    This method is executed when receiving a GET_FILE package on tcp socket.
    It processes the received GET_FILE package contents and if everything
    goes as planned calls the send_get_data_and_get_end_packages function.
    :param received_package_unpacked: received get_file pdu
    :param client_ip_address: ip address of client that sent received_package_unpacked
    :param socket: socket where received_package_unpacked was received and which will
    be used for further communication with client
    """
    client_name = received_package_unpacked[1].split("\x00")[0]
    client_mac_address = received_package_unpacked[2].split("\x00")[0]
    client_random_num = int(received_package_unpacked[3].split("\x00")[0])
    client = get_client_from_name(client_name)

    # check if file can be opened to read
    try:
        client_conf_file = open(client_name + ".cfg", 'r')
    except IOError:
        if debug_mode:
            print_message(
                "DEBUG -> Declined GET_FILE request. File " + client_name +
                ".cfg cannot be accessed or does not exist. " + "Client:" +  client_name + ", ip:" +
                client_ip_address + ", mac:" + client_mac_address)

        get_rej = construct_get_rej_package("file " + client_name + ".cfg cannot be accessed. ")
        send_package_via_tcp_to_client(get_rej, socket)
        socket.close()
        return

    clients_data_mutex.acquire()
    if not are_name_and_mac_valid(client_name, client_mac_address) or client.state == \
            "DISCONNECTED":
        if debug_mode:
            print_message(
                "DEBUG -> Declined GET_FILE request. Client:" + client_name + ", ip:" +
                client_ip_address + ", mac:" + client_mac_address + str(" (not allowed)" if not
                are_name_and_mac_valid(client_name, client_mac_address)
                                                                        else " (not registered)"))

        get_rej = construct_get_rej_package("not allowed" if not
        are_name_and_mac_valid(client_name, client_mac_address) else "not registered")
        clients_data_mutex.release()
        send_package_via_tcp_to_client(get_rej, socket)
        socket.close()
        client_conf_file.close()
        return

    elif not are_random_num_and_ip_address_valid(client_name, client_random_num, client_ip_address)\
            or client.conf_tcp_socket is not None:
        if debug_mode and client.conf_tcp_socket is None:
            print_message("DEBUG -> Error in received GET_FILE. Client:" + client_name + " ip:" +
                          client_ip_address + ", mac:" + client_mac_address + ", rand_num:" +
                          str(client_random_num) + " (Registered as: " + client.name + ", ip:" +
                          client.ip_address + ", mac:" + client.mac_address +
                          ", rand_num:" + str(client.random_num) + ")")

        if client.conf_tcp_socket is not None:
            print_message("INFO -> There already is an operation on configuration file going on. "
                          "Client:" + client_name + " ip:" +client_ip_address +
                          ", mac:" + client_mac_address + ", rand_num:" +
                          str(client_random_num) + " (Registered as: " + client.name + ", ip:" +
                          client.ip_address + ", mac:" + client.mac_address +
                          ", rand_num:" + str(client.random_num) + ")")
            clients_data_mutex.release()
            get_nack = construct_get_nack_package("existant operation already going on")
        else:
            clients_data_mutex.release()
            get_nack = construct_get_nack_package("wrong data received")

        send_package_via_tcp_to_client(get_nack, socket)
        socket.close()
        client_conf_file.close()
        return

    else:  # everything correct
        client.conf_tcp_socket = socket
        clients_data_mutex.release()
        print_message("INFO  -> Accepted configuration file obtaining request. Client: " +
                      client_name + ", ip: " + client_ip_address + ", mac: " +
                      ", random num: " + str(client_random_num))
        get_ack = construct_get_ack_package(client_name, client_random_num)
        send_package_via_tcp_to_client(get_ack, socket)

        send_get_data_and_get_end_packages(socket, client_conf_file, client_random_num)
        client_conf_file.close()
        socket.close()
        clients_data_mutex.acquire()
        client.conf_tcp_socket = None
        clients_data_mutex.release()


def construct_get_rej_package(reason):
    get_rej = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_REJ"), "",
                          "000000000000", "000000", reason)
    return get_rej


def construct_get_nack_package(reason):
    get_nack = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_NACK"), "",
                           "000000000000", "000000", reason)
    return get_nack


def construct_get_ack_package(client_name, client_random_num):
    get_ack = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_ACK"),
                          server_data.name, server_data.mac_address, str(client_random_num),
                          client_name + ".cfg")
    return get_ack


def send_get_data_and_get_end_packages(socket, client_conf_file, client_random_num):
    for line in client_conf_file:
        get_data = construct_get_data(line, client_random_num)
        send_package_via_tcp_to_client(get_data, socket)
    get_end = construct_get_end(client_random_num)
    send_package_via_tcp_to_client(get_end, socket)


def construct_get_data(data_to_fill, client_random_num):
    get_data = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_DATA"),
                           server_data.name, server_data.mac_address, str(client_random_num),
                           data_to_fill)
    return get_data


def construct_get_end(client_random_num):
    get_end = struct.pack('B7s13s7s150s', get_packet_type_from_string("GET_END"),
                          server_data.name, server_data.mac_address, str(client_random_num),
                          "")
    return get_end


def construct_send_rej_package(reason):
    send_rej = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_REJ"), "",
                           "000000000000", "000000", reason)
    return send_rej


def send_package_via_tcp_to_client(package_to_send, socket):
    socket.sendall(package_to_send)
    package_to_send_unpacked = struct.unpack('B7s13s7s150s', package_to_send)
    if debug_mode:
        print_message("DEBUG -> Sent " + get_packet_string_from_type(package_to_send_unpacked[0])
                      + ";\n" + "\t\t\t Bytes: " + str(struct.calcsize('B7s13s7s50s')) + ",\n" +
                      "\t\t\t name: " + package_to_send_unpacked[1].split("\x00")[0] + ",\n" +
                      "\t\t\t mac: " + package_to_send_unpacked[2].split("\x00")[0] + ",\n" +
                      "\t\t\t rand num: " + package_to_send_unpacked[3].split("\x00")[0] + ",\n" +
                      "\t\t\t data: " + package_to_send_unpacked[4].split("\x00")[0] + "\n")


def construct_send_nack_package(reason):
    send_nack = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_NACK"), "",
                            "000000000000", "000000", reason)
    return send_nack


def construct_send_ack_package(client_name, client_random_num):
    send_ack = struct.pack('B7s13s7s150s', get_packet_type_from_string("SEND_ACK"),
                           server_data.name, server_data.mac_address, str(client_random_num),
                           client_name + ".cfg")
    return send_ack


def keep_in_touch_send_data(client, send_data_max_timeout):
    """
    Makes sure client stays in touch with server on tcp socket
    by checking whether lient.is_data_received is True before a countdown.
    :param client: client that must keep in touch
    :param send_data_max_timeout: datetime object that represents the receiving limit time
    """
    try:
        while datetime.now() < send_data_max_timeout:
            if client.is_data_received:
                send_data_max_timeout = datetime.now() + timedelta(seconds=W)
                client.is_data_received = False
            if client.is_end_data_received:
                return
        if not client.is_end_data_received:
            print_message("INFO  -> Not received information on TCP socket during " + str(W) +
                          " seconds")
            client.data_received_timeout_exceeded = True
            return
    # datetime.now() is None when main thread exits, so could throw AttributeError
    except AttributeError:
        return


def save_send_data_packages(socket, file_to_fill,  client):
    """
    This function is executed when receiving a correct SEND_FILE
    package from a client. The goal is to save in a file all the
    future SEND_DATA packages received.
    :param socket: socket where SEND_DATA packages will be received.
    :param file_to_fill: file to fill up with the payload in SEND_DATA pdu
    :param client: client to send the packages
    """
    while not client.data_received_timeout_exceeded:
        received_package_packed = socket.recv(178)
        received_package_unpacked = struct.unpack('B7s13s7s150s', received_package_packed)
        package_type = received_package_unpacked[0]
        client_name = received_package_unpacked[1].split("\x00")[0]
        client_mac_address = received_package_unpacked[2].split("\x00")[0]
        random_num = received_package_unpacked[3].split("\x00")[0]
        data = received_package_unpacked[4].split("\x00")[0]

        if client.data_received_timeout_exceeded:
            break
        if debug_mode:
            print_message("DEBUG -> \t\t Received " + get_packet_string_from_type(package_type) +
                          "; \n" + "\t\t\t\t\t  Bytes: " + str(178) + ", \n" +
                          "\t\t\t\t\t  name: " + client_name + ", \n" +
                          "\t\t\t\t\t  mac: " + client_mac_address + ", \n" +
                          "\t\t\t\t\t  rand num: " + random_num + ", \n" +
                          "\t\t\t\t\t  data: " + data + "\n")

        if received_package_unpacked[0] != get_packet_type_from_string("SEND_END"):
            file_to_fill.write(data)
        else:
            print_message("INFO  -> Client succesfully ended sending of configuration file. "
                          "Client: " + client.name + ", ip:" + client.ip_address +", mac:" +
                          client.mac_address + ", random num: " + str(client.random_num))
            break


def serve_udp_connection(received_package_unpacked, client_ip_address, client_udp_port):
    package_type = received_package_unpacked[0]

    if package_type == get_packet_type_from_string("REGISTER_REQ"):
        serve_register_req(received_package_unpacked, client_ip_address, client_udp_port)
    elif package_type == get_packet_type_from_string("ALIVE_INF"):
        serve_alive_inf(received_package_unpacked, client_ip_address, client_udp_port)


def serve_register_req(received_package_unpacked, client_ip_address, client_udp_port):
    """
    This function is executed when receiving an ALIVE_INF pdu.
    It processes the contents of the received ALIVE_INF pdu.
    If the client's state is DISCONNECTED and the ALIVE_INF pdu received is
    correct, then executes the keep_in_touch function.
    :param received_package_unpacked: alive_inf pdu received that must be processed
    :param client_ip_address: client that sent received_package_unpacked
    :param client_udp_port: udp port where received_package_unpacked has been received
    """
    try:
        client_name = received_package_unpacked[1].split("\x00")[0]
        client_mac_address = received_package_unpacked[2].split("\x00")[0]
        random_num = int(received_package_unpacked[3].split("\x00")[0])

        if not are_name_and_mac_valid(client_name, client_mac_address):
            if debug_mode:
                print_message(
                    "DEBUG -> Declined REG_REQUEST. Client:" + client_name + ", ip:" +
                    client_ip_address + ", mac:" + client_mac_address + " (not allowed)")
            register_rej = construct_register_rej_package("Client not allowed in system")
            send_package_via_udp_to_client(register_rej, client_udp_port, client_ip_address)
            return

        client = get_client_from_name(client_name)
        if client.state == "DISCONNECTED":
            if random_num != 000000:
                if debug_mode:
                    print_message("DEBUG -> Declined REG_REQUEST. REGISTER_REQ's rand "
                                  "is not 000000")
                register_nack = construct_register_nack_package("wrong data received")
                send_package_via_udp_to_client(register_nack, client_udp_port, client_ip_address)
                return
            # save client's ip address and udp port
            clients_data_mutex.acquire()
            client.ip_address = client_ip_address
            client.udp_port = client_udp_port
            change_client_state(client_name, "REGISTERED")
            clients_data_mutex.release()

            alive_inf_timeout = datetime.now() + timedelta(seconds=(J * R))
            register_ack = construct_register_ack_package(get_client_random_num(client_name))
            send_package_via_udp_to_client(register_ack, client_udp_port, client_ip_address)

            keep_in_touch_with_client(client, alive_inf_timeout)

        elif client.state == "REGISTERED" or client.state == "ALIVE":
            if not are_random_num_and_ip_address_valid(client_name, random_num, client_ip_address):
                if debug_mode:
                    print_message(
                        " DEBUG -> Error in received REGISTER_REQ. Client:" + client_name + ", ip:"
                        + client_ip_address + ", mac:" + client_mac_address + ", rand_num:" +
                        str(random_num) + " (Registered as: " + client.name + ", ip:" +
                        client.ip_address + ", mac:" + client.mac_address + ", rand_num:" +
                        str(client.random_num) + ")")
                register_nack = construct_register_nack_package("wrong data received")
                send_package_via_udp_to_client(register_nack, client_udp_port, client_ip_address)
                return

            clients_data_mutex.acquire()
            change_client_state(client_name, "REGISTERED")
            clients_data_mutex.release()
            register_ack = construct_register_ack_package(get_client_random_num(client_name))
            send_package_via_udp_to_client(register_ack, client_udp_port, client_ip_address)
    # datetime.now() is None when main thread exits, so could throw AttributeError
    except AttributeError:
        return


def get_client_from_udp_port_and_ip(udp_port, ip_address):
    for valid_client in valid_clients_data:
        if udp_port == valid_client.udp_port and ip_address == valid_client.ip_address:
            return valid_client
    return None


def are_name_and_mac_valid(client_name, client_mac_address):
    for valid_client in valid_clients_data:
        if str(valid_client.name) == client_name:
            if valid_client.mac_address == client_mac_address:
                return True
            break
    return False


def construct_register_rej_package(reason):
    register_rej = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_REJ"), "",
                               "000000000000", "000000", reason)
    return register_rej


def send_package_via_udp_to_client(package_to_send, to_udp_port, to_ip_address):
    sockets.udp_socket.sendto(package_to_send, (to_ip_address, to_udp_port))
    package_to_send_unpacked = struct.unpack('B7s13s7s50s', package_to_send)
    if debug_mode:
        print_message("DEBUG -> Sent " + get_packet_string_from_type(package_to_send_unpacked[0])
                      + ";\n" + "\t\t\t Bytes: " + str(struct.calcsize('B7s13s7s50s')) + ",\n" +
                      "\t\t\t name: " + package_to_send_unpacked[1].split("\x00")[0] + ",\n" +
                      "\t\t\t mac: " + package_to_send_unpacked[2].split("\x00")[0] + ",\n" +
                      "\t\t\t rand num: " + package_to_send_unpacked[3].split("\x00")[0] + ",\n" +
                      "\t\t\t data: " + package_to_send_unpacked[4].split("\x00")[0] + "\n")


def get_client_from_name(client_name):
    for valid_client in valid_clients_data:
        if valid_client.name == client_name:
            return valid_client
    return None


def get_client_state(client_name):
    for valid_client in valid_clients_data:
        if valid_client.name == client_name:
            return valid_client.state
    return None


def construct_register_nack_package(reason):
    register_nack = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_NACK"), "",
                                "000000000000", "000000", reason)
    return register_nack


def get_client_random_num(client_name):
    for valid_client in valid_clients_data:
        if valid_client.name == client_name:
            return valid_client.random_num
    return None


def construct_register_ack_package(client_random_num):
    register_ack = struct.pack('B7s13s7s50s', get_packet_type_from_string("REGISTER_ACK"),
                               server_data.name,server_data.mac_address, str(client_random_num),
                               str(sockets.tcp_port))
    return register_ack


def change_client_state(client_name, new_state):
    for valid_client in valid_clients_data:
        if valid_client.name == client_name:
            if valid_client.state != new_state:
                valid_client.state = new_state
                if new_state == "REGISTERED" and debug_mode:
                    print_message("INFO  -> Client: " + valid_client.name +
                                  " successfully signed up on server; " +
                                  " ip: " + valid_client.ip_address + " mac: " +
                                  valid_client.mac_address + " rand_num: " +
                                  str(valid_client.random_num))
                print_message("INFO  -> Client " + client_name + " changed its state to: "
                              + new_state)
            else:
                if new_state == "REGISTERED" and debug_mode:
                    print_message("DEBUG -> Client 'changed' its state to REGISTERED "
                                  "(Duplicated signup)")


def are_random_num_and_ip_address_valid(client_name, to_check_random_num, to_check_ip_address):
    for valid_client in valid_clients_data:
        if valid_client.name == client_name:
            return valid_client.ip_address == to_check_ip_address and \
                   valid_client.random_num == to_check_random_num
    return False


def keep_in_touch_with_client(client, first_alive_inf_timeout):
    """
    Makes sure client stays in touch with server using udp socket by checking whether
    client.is_alive_received is True before a countdown.
    client.is_alive_received is changed to True on serve_alive_inf function when
    receiving an ALIVE_INF pdu and then changed to False inside this function.
    :param client: client that must keep in touch
    :param first_alive_inf_timeout: maximum datetime to receive first alive_inf
    """

    while True:
        try:
            if client.state == "REGISTERED":
                is_first_alive_received = False
                while datetime.now() < first_alive_inf_timeout:
                    if client.is_alive_received:
                        is_first_alive_received = True
                        clients_data_mutex.acquire()
                        client.is_alive_received = False
                        clients_data_mutex.release()
                    time.sleep(0.01)
                if not is_first_alive_received:
                    print_message("INFO  -> Have not received first ALIVE_INF in "
                                  + str(J * R) + " seconds")
                    clients_data_mutex.acquire()
                    change_client_state(client.name, "DISCONNECTED")
                    clients_data_mutex.release()
                    return

            elif client.state == "ALIVE":
                alive_inf_timeout = datetime.now() + timedelta(seconds=R)
                is_alive_received = False
                while datetime.now() < alive_inf_timeout:
                    if client.is_alive_received:
                        clients_data_mutex.acquire()
                        client.consecutive_non_received_alives = 0
                        client.is_alive_received = False
                        clients_data_mutex.release()
                    time.sleep(0.01)
                if not is_alive_received:
                    clients_data_mutex.acquire()
                    client.consecutive_non_received_alives += 1
                    if client.consecutive_non_received_alives == K:
                        print_message("INFO  -> Have not received " + str(K) +
                                      " consecutive ALIVES")
                        change_client_state(client.name, "DISCONNECTED")
                        client.consecutive_non_received_alives = 0
                        clients_data_mutex.release()
                        return
                    clients_data_mutex.release()
        # datetime.now() is None when main thread exits, so could throw AttributeError
        except AttributeError:
            return


def serve_alive_inf(received_package_unpacked, client_ip_address, client_udp_port):
    """
    This function is executed when receiving an ALIVE_INF pdu.
    It processes the contents of the received ALIVE_INF pdu and lets the
    keep_in_touch_with_client function know that an ALIVE_INF for an specific client
    has been received.
    :param received_package_unpacked: alive_inf pdu received that must be processed
    :param client_ip_address: client that sent received_package_unpacked
    :param client_udp_port: udp port where received_package_unpacked has been received
    """
    client_name = received_package_unpacked[1].split("\x00")[0]
    client_mac_address = received_package_unpacked[2].split("\x00")[0]
    random_num = int(received_package_unpacked[3].split("\x00")[0])
    client = get_client_from_name(client_name)

    client_from_udp_and_ip = get_client_from_udp_port_and_ip(client_udp_port, client_ip_address)
    if client_from_udp_and_ip is not None:
        # assignment targets keep_in_touch_with_client function
        client_from_udp_and_ip.is_alive_received = True
    clients_data_mutex.acquire()

    if not are_name_and_mac_valid(client_name, client_mac_address) or \
            client.state != "REGISTERED" and client.state != "ALIVE":
        if debug_mode:
            print_message(
                "DEBUG -> Declined ALIVE_INF. Client:" + client_name + ", ip:" + client_ip_address +
                ", mac:" + client_mac_address + str(" (not allowed)" if not
                are_name_and_mac_valid(client_name, client_mac_address) else " (not registered)"))

        alive_rej = construct_alive_rej_package(
            str("not allowed" if not are_name_and_mac_valid(client_name, client_mac_address)
                else "not registered"))
        clients_data_mutex.release()
        send_package_via_udp_to_client(alive_rej, client_udp_port, client_ip_address)
        return

    elif not are_random_num_and_ip_address_valid(client_name, random_num, client_ip_address):
        if debug_mode:
            print_message(
                "DEBUG -> Error in received ALIVE_INF. Client:" + client_name + " ip:" +
                client_ip_address + ", mac:" + client_mac_address + ", rand_num:" +
                str(random_num) + " (Registered as: " + client.name +", ip:" + client.ip_address +
                ", mac:" + client.mac_address + ", rand_num:" + str(client.random_num) + ")")

        clients_data_mutex.release()
        alive_nack = construct_alive_nack_package("wrong data received")
        send_package_via_udp_to_client(alive_nack, client_udp_port, client_ip_address)
        return
    else:  # everything correct
        change_client_state(client.name, "ALIVE")
        clients_data_mutex.release()
        alive_ack = construct_alive_ack_package(client.random_num)
        send_package_via_udp_to_client(alive_ack, client_udp_port, client_ip_address)


def construct_alive_rej_package(reason):
    alive_rej = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_REJ"), "",
                            "000000000000", "000000", reason)
    return alive_rej


def construct_alive_nack_package(reason):
    alive_nack = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_NACK"), "",
                             "000000000000", "000000", reason)
    return alive_nack


def construct_alive_ack_package(client_random_num):
    alive_ack = struct.pack('B7s13s7s50s', get_packet_type_from_string("ALIVE_ACK"),
                            server_data.name, server_data.mac_address, str(client_random_num), "")
    return alive_ack


# input: ./server.py {-d} {-c <software_config_file>}
#         {-u <allowed_devices_file>}
if __name__ == '__main__':
    try:
        # create thread (daemon) to handle stdin
        thread_for_stdin = threading.Thread(target=manage_command_line_input)
        thread_for_stdin.daemon = True
        thread_for_stdin.start()
        parse_argv(sys.argv)
        setup_udp_socket()
        setup_tcp_socket()
        service()
    except(KeyboardInterrupt, SystemExit):
        # close client conf sockets (if any in use)
        clients_data_mutex.acquire()
        for client in valid_clients_data:
            if client.conf_tcp_socket is not None:
                client.conf_tcp_socket.close()
        clients_data_mutex.release()
        print  # simply prints new line
        print_message("Exiting server...")
        sockets.udp_socket.close()
        sockets.tcp_socket.close()
        exit(1)  # does exit all daemon threads as well
