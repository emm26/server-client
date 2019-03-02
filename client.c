#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <sys/select.h>

// program flow and execution defined variables
#define M 4
#define N 3
#define P 8
#define Q 3
#define S 5
#define T 2

// global variables
bool debug_mode = false;
FILE *network_dev_config_file = NULL;
struct DeviceData device_data;
struct ServerData server_data;
struct Sockets sockets;
char *client_state = NULL;

// Simulates PDU for signup and keep in touch with server purposes
struct Package {
    unsigned char type;
    char dev_name[7];
    char mac_address[13];
    char dev_random_num[7];
    char data[50];
};

// Simulates PDU for send-conf and get-conf purposes
struct PackageForCommands {
    unsigned char type;
    char dev_name[7];
    char mac_address[13];
    char dev_random_num[7];
    char data[150];
};

// device = machine where the client is running
struct DeviceData {
    char dev_name[9];
    char dev_mac[13];
    char dev_random_num[7];
};

struct ServerData {
    char *server_name_or_address;
    int server_udp_port;
};

struct Sockets {
    int udp_socket;
    struct sockaddr_in  udp_addr_server;
    int tcp_socket;
};

// functions declaration
void end_handler(int signal);
void change_client_state(char *new_state);
void parse_argv(int argc, const char  *argv[]);
void parse_and_save_software_config_file_data(FILE *software_config_file);
void print_message(char *to_print);
void signup_on_server();
void setup_UDP_socket();
void send_package_via_udp_to_server(struct Package package_to_send, char* currentFunction);
int get_waiting_time_after_sent(int reg_reqs_sent);
unsigned char get_packet_type_from_string();
struct Package construct_register_request_package();
struct Package receive_package_via_udp_from_server();

/* input: ./client -c <software_config_file> -d 
          -f <network_dev_config_file>       */
int main(int argc, const char* argv[]){
    signal(SIGINT, end_handler);
    parse_argv(argc, argv);
    signup_on_server();
    /*  TO DO
       thread 1
       keep_in_touch_with_server();
       thread 2
       wait_for_commands();
       join threads */
    return 0;
}

// functions implementation

void end_handler(int signal){
    if (signal == SIGINT){
        write(2, "\nExiting client...\n", 35);
        exit(0);
    }
}

void parse_argv(int argc, const char* argv[]){
    FILE *software_config_file = NULL;
    for(int i = 0; i < argc; i++){
        if(strcmp(argv[i], "-c") == 0){
            if(argc > i){ software_config_file = fopen(argv[i+1], "r"); }
        } else if(strcmp(argv[i], "-d") == 0){
            debug_mode = true;
            print_message("INFO -> Debug mode enabled\n");
        } else if(strcmp(argv[i], "-f") == 0){
            if(argc > i){ network_dev_config_file = fopen(argv[i+1], "r"); }
        }
    }

    if (debug_mode){ print_message("DEBUG -> Read command line input\n");}

    if (software_config_file == NULL){ // open default
        software_config_file = fopen("client.cfg", "r");
    }
    if (network_dev_config_file == NULL){ // open default
        network_dev_config_file = fopen("boot.cfg", "r");
    }
    parse_and_save_software_config_file_data(software_config_file);

    if(debug_mode){ print_message("DEBUG -> Read data from configuration files\n");}
}

void parse_and_save_software_config_file_data(FILE *software_config_file){
    char line[70];
    char delim[] = " \n";
    char *token;

    // read line by line
    while (fgets(line, 70, software_config_file)){
        // split line to get attribute and value from line
        token = strtok(line, delim);

        if (strcmp(token, "Nom") == 0){
            token = strtok(NULL, delim);
            strcpy(device_data.dev_name, token);
        } else if (strcmp(token, "MAC") == 0){
            token = strtok(NULL, delim);
            strcpy(device_data.dev_mac, token);
        } else if (strcmp(token, "Server") == 0){
            token = strtok(NULL, delim);
            server_data.server_name_or_address = malloc(strlen(token) + 1);
            strcpy(server_data.server_name_or_address, token);
        } else if (strcmp(token, "Server-port") == 0){
            server_data.server_udp_port = atoi(strtok(NULL, delim));
        }
    }
}

void change_client_state(char *new_state){
    if(client_state == NULL || strcmp(client_state, new_state) != 0){
        client_state = malloc(sizeof(new_state));
        strcpy(client_state, new_state);
        char message[50];
        sprintf(message, "INFO -> Client state changed to: %s\n", client_state);
        print_message(message);
    }
}

void print_message(char *to_print){
    time_t now;
    struct tm *now_tm;
    int hour, minutes, secs;

    now = time(NULL);
    now_tm = localtime(&now);
    hour = now_tm->tm_hour;
    minutes = now_tm->tm_min;
    secs = now_tm->tm_sec;
    printf("%d:%d:%d - %s", hour, minutes, secs, to_print);
}

unsigned char get_packet_type_from_string(char *string){
    unsigned char packet_type;

    // signup process packet types
    if (strcmp(string, "REGISTER_REQ") == 0){
        packet_type = (unsigned char) 0x00;
    } else if (strcmp(string, "REGISTER_ACK") == 0){
        packet_type = (unsigned char) 0x01;
    } else if (strcmp(string, "REGISTER_NACK") == 0){
        packet_type = (unsigned char) 0x02;
    } else if (strcmp(string, "REGISTER_REJ") == 0){
        packet_type = (unsigned char) 0x03;
    } else if (strcmp(string, "ERROR") == 0){
        packet_type = (unsigned char) 0x09;
    }

    return packet_type;
}

char* get_packet_string_from_type(unsigned char type){
    char*  packet_string;

    // signup process packet types
    if (type == (unsigned char) 0x00){
        packet_string = "REGISTER_REQ";
    } else if (type == (unsigned char) 0x01){
        packet_string = "REGISTER_ACK";
    } else if (type == (unsigned char) 0x02){
        packet_string = "REGISTER_NACK";
    } else if (type == (unsigned char) 0x03) {
        packet_string = "REGISTER_REJ";
    } else if (type == (unsigned char) 0x09) {
        packet_string = "ERROR";
    }

    return packet_string;
}

void signup_on_server(){
    setup_UDP_socket();
    for (int reg_processes_without_ack_received = 0; reg_processes_without_ack_received < Q;
             reg_processes_without_ack_received++) {

        change_client_state("DISCONNECTED");
        for (int register_reqs_sent = 0; register_reqs_sent < P; register_reqs_sent++){
            struct Package register_req = construct_register_request_package();
            struct Package server_answer;
            send_package_via_udp_to_server(register_req, "SIGNUP");
            change_client_state("WAIT_REG");
            sleep(get_waiting_time_after_sent(register_reqs_sent));
            server_answer = receive_package_via_udp_from_server();
            if (server_answer.type == get_packet_type_from_string("REGISTER_REJ")){
                change_client_state("DISCONNECTED");
                exit(1);
            } else if (server_answer.type == get_packet_type_from_string("REGISTER_NACK")){
                break;
            } else if (server_answer.type == get_packet_type_from_string("REGISTER_ACK")){
                change_client_state("REGISTERED");
                return;
            } // else: NO_ANSWER -> Keep trying to contact server, keep looping
            if(debug_mode){
                print_message("DEBUG -> No answer received for REGISTER_REQ\n");
                print_message("DEBUG -> Trying to reach server again...\n");
            }
        }

        sleep(S);
        if (debug_mode) {
            char message[75];
            printf("\n");
            sprintf(message, "INFO -> Starting new signup process. Current tries: %d / %d\n",
                    reg_processes_without_ack_received + 1, Q);
            print_message(message);
        }

    }
    print_message("ERROR -> Could not contact server during SIGNUP\n");
    print_message("ERROR -> Maximum tries to contact server without REGISTER_ACK received reached\n");
    exit(1);
}

void setup_UDP_socket(){
    struct hostent *ent;
    struct sockaddr_in addr_cli;

    // gets server identity
    ent = gethostbyname(server_data.server_name_or_address);
    if(!ent){
        print_message("ERROR -> Can't find server on trying to setup UDP socket\n");
        exit(1);
    }

    // create INET+DGRAM socket -> UDP
    sockets.udp_socket = socket(AF_INET,SOCK_DGRAM,0);  
    if(sockets.udp_socket < 0){
        print_message("ERROR -> Could not create UDP socket\n");
        exit(1);
    }

    // fill the structure with the addresses where we will bind the client (any local address)
    memset(&addr_cli,0,sizeof (struct sockaddr_in));
    addr_cli.sin_family=AF_INET;
    addr_cli.sin_addr.s_addr=htonl(INADDR_ANY);
    addr_cli.sin_port=htons(0);

    // bind
    if(bind(sockets.udp_socket,(struct sockaddr *)&addr_cli,sizeof(struct sockaddr_in)) < 0)
    {
        print_message("ERROR -> Could not bind UDP socket\n");
        exit(1);
    }

    // fill the structure of the server's address where we will send the data
    memset(&sockets.udp_addr_server,0,sizeof (struct sockaddr_in));
    sockets.udp_addr_server.sin_family=AF_INET;
    sockets.udp_addr_server.sin_addr.s_addr=(((struct in_addr *)ent->h_addr_list[0])->s_addr);
    sockets.udp_addr_server.sin_port=htons(server_data.server_udp_port);

}

struct Package construct_register_request_package(){
    struct Package register_req;

    // fill Package
    register_req.type = get_packet_type_from_string("REGISTER_REQ");
    strcpy(register_req.dev_name, device_data.dev_name);
    strcpy(register_req.mac_address, device_data.dev_mac);
    strcpy(register_req.dev_random_num, "000000");
    strcpy(register_req.data, "");

    return register_req;
}

void send_package_via_udp_to_server(struct Package package_to_send, char* currentFunction){
    int a;
    a = sendto(sockets.udp_socket, &package_to_send, sizeof(package_to_send), 0,
               (struct sockaddr *) &sockets.udp_addr_server, sizeof(sockets.udp_addr_server));
    char message[150];
    if (a < 0) {
        sprintf(message, "ERROR -> Could not send package via UDP socket during %s\n", currentFunction);
        print_message(message);
    } else if (debug_mode) {
        sprintf(message,
                "DEBUG -> Sent %s;\n"
                "\t\t\tBytes:%lu,\n"
                "\t\t\tname:%s,\n "
                "\t\t\tmac:%s,\n"
                "\t\t\talea:%s,\n"
                "\t\t\tdata:%s\n\n",
                get_packet_string_from_type(package_to_send.type), sizeof(package_to_send),
                package_to_send.dev_name, package_to_send.mac_address, package_to_send.dev_random_num,
                package_to_send.data);
        print_message(message);
    }
}

int get_waiting_time_after_sent(int reg_reqs_sent){ // note: reg_reqs_sent starts at 0
    if(reg_reqs_sent >= N-1){
        int times = 2 + (reg_reqs_sent + 1 - N);
        if(times > M){
            times = M;
        }
        return times * T;
    }
    return T;
}


struct Package receive_package_via_udp_from_server(){
    fd_set rfds;
    struct timeval timeout;
    char* buf = malloc(sizeof(struct Package));
    struct Package* package_received = malloc(sizeof(struct Package));

    FD_ZERO(&rfds); // clears set
    FD_SET(sockets.udp_socket, &rfds); // add socket descriptor to set
    timeout.tv_sec = 0;
    timeout.tv_usec = 0; // return immediately
    // if any data is in socket
    if(select(sockets.udp_socket + 1, &rfds, NULL, NULL, &timeout) > 0){
        // receive from socket
        int a;
        a = recvfrom(sockets.udp_socket, buf, sizeof(struct Package), 0, (struct sockaddr*) 0, (socklen_t*) 0);
        if (a < 0) {
            print_message("ERROR -> Could not receive from UDP socket\n");
        } else {
            package_received = (struct Package *) buf;
            if (debug_mode) {
                char message[200];
                sprintf(message,
                        "DEBUG -> Received %s;\n"
                        "\t\t\t    Bytes:%lu,\n"
                        "\t\t\t    name:%s,\n "
                        "\t\t\t    mac:%s,\n"
                        "\t\t\t    alea:%s,\n"
                        "\t\t\t    data:%s\n\n",
                        get_packet_string_from_type((unsigned char) (*package_received).type),
                        sizeof(*package_received), (*package_received).dev_name,
                        (*package_received).mac_address, (*package_received).dev_random_num,
                        (*package_received).data);
                print_message(message);
            }
        }
    }
    return *(package_received);
} 

