#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>

// program flow and execution defined variables
#define M 4
#define N 3
#define P 8
#define Q 3
#define S 5
#define T 2

// global variables
bool debug_mode = false;
FILE *network_dev_config_file;
struct DeviceData device_data;
struct ServerData server_data;
struct Sockets sockets;
char *client_state;

// structs
struct Package {
    unsigned char type;
    char dev_name[7];
    char mac_address[13];
    char dev_random_num[7];
    char *data;
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
    int tcp_socket;
}

// functions declaration
void change_client_state(char *new_state);
void parse_argv(int argc, const char  *argv[]);
void parse_and_save_software_config_file_data(FILE *software_config_file);
void print_message(char *to_print);
void send_package_via_udp_to_server(struct Package package_to_send);
int get_waiting_time_after_sent(int reg_reqs_sent);
int signup_on_server();
unsigned char* get_packet_type_from_string();
struct Package construct_register_request_package();
struct Package receive_package_via_udp_from_server();

/* input: ./client -c <software_config_file> -d 
          -f <network_dev_config_file>       */
int main(int argc, const char* argv[]){
    parse_argv(argc, argv);
    if (signup_on_server() == 0){
        /* TO DO
           thread 1
           keep_in_touch_with_server();
           thread 2
           wait_for_commands();
           join threads */
        return 0;
    }
    return 1;
}

// functions implementation
void parse_argv(int argc, const char* argv[]){
    FILE *software_config_file;

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-c") == 0){
            software_config_file = fopen(argv[i+1], "r");
        } else if(strcmp(argv[i], "-d") == 0){
            debug_mode = true;
            print_message("Debug mode enabled \n");
        } else if(strcmp(argv[i], "-f") == 0){
            network_dev_config_file = fopen(argv[i+1], "r");
        }
    }

    if (software_config_file == NULL){ // open default
        software_config_file = fopen("client.cfg", "r");
    }
    if (network_dev_config_file == NULL){ // open default
        network_dev_config_file = fopen("boot.cfg", "r");
    }
    parse_and_save_software_config_file_data(software_config_file);
}

void parse_and_save_software_config_file_data(FILE *software_config_file){
    char *line;
    char delim[] = " \n";
    ssize_t read;
    size_t len = 0;
    char *token;

    // read line by line
    while ((read = getline(&line, &len, software_config_file)) != -1){
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
            server_data.server_udp_port = (int) strtok(NULL, delim);
        }
    }
}

void change_client_state(char *new_state){
    if(strcmp(client_state, new_state) != 0){
        strcpy(client_state, new_state);
        char *message = NULL;
        sprintf(message, "Client state changed to: %s\n", client_state);
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
    printf("%d:%d:%d -> %s", hour, minutes, secs, to_print);
}

unsigned char* get_packet_type_from_string(char *string){
    unsigned char* packet_type = malloc(sizeof(unsigned char));

    // signup process packet types
    if (strcmp(string, "REGISTER_REQ") == 0){
        packet_type = (unsigned char*) 0x00;
    } else if (strcmp(string, "REGISTER_ACK") == 0){
        packet_type = (unsigned char*) 0x01;
    } else if (strcmp(string, "REGISTER_NACK") == 0){
        packet_type = (unsigned char*) 0x02;
    } else if (strcmp(string, "REGISTER_REJ") == 0){
        packet_type = (unsigned char*) 0x03;
    } else if (strcmp(string, "ERROR") == 0){
        packet_type = (unsigned char*) 0x09;
    }

    return packet_type;
}

int signup_on_server(){
    setup_UDP_Socket();
    for (int reg_processes_without_ack_received = 0; reg_processes_without_ack_received < Q; reg_processes_without_ack_received++){
        change_client_state("DISCONNECTED");
        for (int register_reqs_sent = 0; register_reqs_sent < P; register_reqs_sent++){
            struct Package register_req = construct_register_request_package();
            struct Package server_answer;
            int waiting_time_after_sent = get_waiting_time_after_sent(register_reqs_sent);
            send_package_via_udp_to_server(register_req);
            change_client_state("WAIT_REG");
            sleep(waiting_time_after_sent);
            server_answer = receive_package_via_udp_from_server();
            if (server_answer.type == *(get_packet_type_from_string("REGISTER_REJ"))){
                change_client_state("DISCONNECTED");
                print_message("SIGNUP: ERROR -> Received REGISTER_REJ from server\n");
                return 1;
            } else if (server_answer.type == *(get_packet_type_from_string("REGISTER_NACK"))){
                if(debug_mode){ print_message("SIGNUP: Received REGISTER_NACK from server\n");}
                break;
            } else if (server_answer.type == *(get_packet_type_from_string("REGISTER_ACK"))){ 
                change_client_state("REGISTERED")   ;
                if(debug_mode){ print_message("SIGNUP: Received REGISTER_ACK from server\n");}
                return 0;
            } // else: NO_ANSWER -> Keep trying to contact server, keep looping
            if(debug_mode){ print_message("SIGNUP: No answer received for REGISTER_REQ. Trying to reach server again...\n");}
        }

        sleep(S);
        if(debug_mode){ 
            char *message = NULL;
            sprintf(message, "SIGNUP: Starting new signup process. Current tries: %d / %d\n", reg_processes_without_ack_received + 1, Q);
            print_message(message);
        }
    }
    print_message("SIGNUP: ERROR -> Could not contact server. Maximum tries to contact server without REGISTER_ACK received have been reached\n");
    return 1;
}

void setup_UDP_socket(){
    struct hostent *ent;
    struct sockaddr_in addr_server,addr_cli;

    // gets server identity
    ent = getHostByName(server_data.server_name_or_address);
    if(!ent){
        print_message("setup UDP socket: ERROR -> Can't find server\n");
        return;
    }

    // Create INET+DGRAM socket -> UDP 
    sockets.udp_socket = socket(AF_INET,SOCK_DGRAM,0);  
    if(sockets.udp_socket < 0){
        print_message("setup UDP socket: ERROR -> Could not create socket\n");   
        return;
    }

    // Ompla l'estructrura d'adreça amb les adreces on farem el binding
    memset(&addr_cli,0,sizeof (struct sockaddr_in));
    addr_cli.sin_family=AF_INET;
    addr_cli.sin_addr.s_addr=htonl(INADDR_ANY);
    addr_cli.sin_port=htons(0);

}

struct Package construct_register_request_package(){
    struct Package register_req;

    // get random num - of 6 digits 
    srand(time(NULL));
    int random_num = rand () % 1000000;
    // convert random num to string
    char random_num_as_string[7];
    sprintf(random_num_as_string, "%d", random_num);
    random_num_as_string[6] = '\0';

    // fill Package
    register_req.type = *(get_packet_type_from_string("REGISTER_REQ"));
    strcpy(register_req.dev_name, device_data.dev_name);
    strcpy(register_req.mac_address, device_data.dev_mac);
    strcpy(register_req.dev_random_num, random_num_as_string);
    register_req.data = malloc(50 * sizeof(char));

    return register_req;

}

void send_package_via_udp_to_server(struct Package package_to_send){
    
}

int get_waiting_time_after_sent(int reg_reqs_sent){
    if(reg_reqs_sent >= N){
        int times = 2 + (reg_reqs_sent - N);
        if(times > M){
            times = M;
        }
        return times * T;
    }
    return T;
}

struct Package receive_package_via_udp_from_server(){

}

