
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <ctype.h> // For isdigit() function
#include <time.h>
#include <pthread.h> // For threading support
#include <signal.h>

#define MAX_CLIENTS 50
#define TIME_STRING_LENGTH 24
#define BUFFER_SIZE 4096

typedef struct {
    char method[10];
    char host[100];
    int port;
    char path[100];
    char version[10];
} HttpRequest;


typedef struct {
    int socket;
    char ip[INET_ADDRSTRLEN];
    char *access_log_file;
    char *forbidden_sites_file;
} ClientInfo;



void sigint_handler(int signum){
    if (signum == SIGINT){
        printf("rereading the forbidden file\n");
    }
}

int is_ip_address(const char *str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str, &(sa.sin_addr)) != 0;
}

void to_lower_case(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = tolower(str[i]);
    }
}

int check_access_control(const char *host, const char *forbidden_file_path) {
    FILE *file = fopen(forbidden_file_path, "r");
    if (file == NULL) {
        perror("Error opening forbidden sites file");
        return 0; // Allow access if file cannot be opened
    }

    // If the provided host is a hostname, resolve it and check for match
    struct addrinfo *result, *rp;
    struct addrinfo hints;
    struct sockaddr_in *addr;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4 addresses only
    hints.ai_socktype = SOCK_STREAM; // TCP socket
    hints.ai_protocol = IPPROTO_TCP; // TCP protocol
    
   
    ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }


    int ip_count = 0;
    char ip_addresses[10][INET_ADDRSTRLEN]; // Array to store IP addresses as strings

    // Iterate through the list of addresses
    for (rp = result; rp != NULL && ip_count < 10; rp = rp->ai_next) {
        addr = (struct sockaddr_in *)rp->ai_addr;
        inet_ntop(AF_INET, &(addr->sin_addr), ip_addresses[ip_count], INET_ADDRSTRLEN);
        ip_count++;
    }
    freeaddrinfo(result); // Free the address list

    // // Print the IP addresses
    // printf("IPv4 addresses for %s:\n", host);
    // for (int i = 0; i < ip_count; i++) {
    //     printf("%s\n", ip_addresses[i]);
    // }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (line==NULL){
            continue;
        }
        // Remove newline character if present
        if (line[strlen(line) - 1] == '\n') {
            line[strlen(line) - 1] = '\0';
        }

        // Trim trailing whitespace
        char *end = line + strlen(line) - 1;
        while (end > line && isspace(*end)) {
            *end-- = '\0';
        }

        // Convert both host and line to lowercase for case insensitivity
        char lower_host[256];
        strcpy(lower_host, host);
        to_lower_case(lower_host);

        char lower_line[256];
        strcpy(lower_line, line);
        to_lower_case(lower_line);


        // Check if the host matches any forbidden site
        if (strcmp(lower_host, lower_line) == 0) {
            fclose(file);
            return 1; // Access is forbidden
        }

        // If the provided host is an IP address, check for exact match
        if (is_ip_address(host) && strcmp(host, line) == 0) {
            fclose(file);
            return 1; // Access is forbidden
        }

        for (int i = 0; i< ip_count; i++){
            if (strcmp(ip_addresses[i], line)==0){
                fclose(file);
                return 1;
            }
        }
    }

    fclose(file);
    return 0; // Allow access
}


char* format_time(const struct tm *timeptr, unsigned int milliseconds) {
    static char result[TIME_STRING_LENGTH];

    // Format the time components
    strftime(result, sizeof(result), "%Y-%m-%dT%H:%M:%S", timeptr);

    // Append milliseconds
    sprintf(result + strlen(result), ".%03d", milliseconds);

    // Append 'Z' for UTC timezone
    strcat(result, "Z");

    return result;
}

char *https_request(const char *request, char* HOST, char *PORT, size_t *response_size) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct addrinfo hints, *res;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SSL context\n");
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx); // Set default verify paths

    // Create TCP socket
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(HOST, PORT, &hints, &res) != 0) {
        fprintf(stderr, "Error getting address info\n");
        return NULL;
    }
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        fprintf(stderr, "Error creating socket\n");
        return NULL;
    }

    // Connect to server
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        fprintf(stderr, "Error connecting to server\n");
        return NULL;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Error creating SSL structure\n");
        return NULL;
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "Error establishing SSL connection\n");
        return NULL;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        fprintf(stderr, "Error retrieving server certificate\n");
        return NULL;
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %s\n", X509_verify_cert_error_string(verify_result));
        return NULL;
    }


    // Send HTTP request
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        fprintf(stderr, "Error sending request\n");
        return NULL;
    }

    // Receive HTTP response
    char response[4096];
    int bytes_received;
    char *full_response = NULL;
    size_t full_response_size = 0;
    while ((bytes_received = SSL_read(ssl, response, sizeof(response) - 1)) > 0) {
        response[bytes_received] = '\0';
        full_response = realloc(full_response, full_response_size + bytes_received + 1);
        if (full_response == NULL) {
            fprintf(stderr, "Memory allocation error\n");
            return NULL;
        }
        memcpy(full_response + full_response_size, response, bytes_received);
        full_response_size += bytes_received;
    }
    full_response[full_response_size] = '\0';

    // Assign the size before cleaning up
    *response_size = full_response_size;

    // Clean up
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    freeaddrinfo(res);

    return full_response;

}


int send_http_response(int client_socket, const char *status, const char *content_type, const char *content) {
    char response[1024];
    snprintf(response, sizeof(response), "HTTP/1.1 %s\r\n"
                                          "Content-Type: %s\r\n"
                                          "Content-Length: %zu\r\n"
                                          "Connection: close\r\n"
                                          "\r\n"
                                          "%s",
             status, content_type, strlen(content), content);
    // Send response to the client
    send(client_socket, response, strlen(response), 0);
    return strlen(response);
}

int send_403_response(int client_socket) {
    const char *status = "403 Forbidden";
    const char *content_type = "text/html";
    const char *content = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>";

    return send_http_response(client_socket, status, content_type, content);
}


char* get_first_line(const char *request) {
    static char first_line[1024];
    const char *newline_pos;

    // Find the position of the first newline character
    newline_pos = strstr(request, "\r\n");
    if (newline_pos == NULL) {
        newline_pos = strchr(request, '\n'); // For cases where lines are terminated with just '\n'
    }

    // Calculate the length of the first line
    size_t line_length = (newline_pos != NULL) ? (size_t)(newline_pos - request) : strlen(request);

    // Copy the first line into the result string
    strncpy(first_line, request, line_length);
    first_line[line_length] = '\0'; // Null-terminate the string

    return first_line;
}



int extract_status_code(const char *response) {
    const char *status_code_start = strstr(response, "HTTP/1.1 ");
    if (status_code_start != NULL) {
        status_code_start += strlen("HTTP/1.1 ");
        return atoi(status_code_start);
    }
    return -1; // Not found
}

void logging(char * access_log_file, char* first, int status, int response_size){
    time_t rawtime;
    struct tm *timeinfo;
    unsigned int miliseconds = 852;
    time(&rawtime);
    timeinfo = gmtime(&rawtime);
    // Format time
    char *formatted_time = format_time(timeinfo, miliseconds);

    // Log request to access log file
    FILE *log_file = fopen(access_log_file, "a");
    if (log_file != NULL) {
        char log_entry[BUFFER_SIZE];
        sprintf(log_entry, "%s 127.0.0.1 '%s' %d %d\n", formatted_time, first, status, response_size);
        fputs(log_entry, log_file);
        fclose(log_file);
    }
}

int send_500_response(int client_socket) {
    const char *status = "500 Internal Server Error";
    const char *content_type = "text/html";
    const char *content = "<html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>The server encountered an unexpected condition that prevented it from fulfilling the request.</p></body></html>";

    return send_http_response(client_socket, status, content_type, content);
}

// Global variables for synchronization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int active_clients = 0;

void *client_handler(void *arg) {

    pthread_mutex_lock(&mutex);

    ClientInfo *client_info = (ClientInfo *)arg;
    int client_socket = client_info->socket;
    char *access_log_file = client_info->access_log_file;
    char *forbidden_sites_file = client_info->forbidden_sites_file;
    char client_ip[INET_ADDRSTRLEN];
    strncpy(client_ip, client_info->ip, INET_ADDRSTRLEN);
    free(client_info);


    char buffer[BUFFER_SIZE];
    size_t response_size;
    memset(buffer, 0, BUFFER_SIZE);

    // Receive request from client
    if (recv(client_socket, buffer, BUFFER_SIZE, 0) < 0) {
        perror("Error receiving request from client");
        close(client_socket);
        return NULL;
    }

    //printf("%s\n", buffer);


    char *first = get_first_line(buffer);

    char method[BUFFER_SIZE];
    char url[BUFFER_SIZE];
    char host[BUFFER_SIZE];
    char port[6] = "443"; 

    if (sscanf(buffer, "%s %s", method, url) != 2) {
        fprintf(stderr, "Error parsing method and URL from request\n");
        close(client_socket);
        return NULL;
    }

    if (strncasecmp(url, "http://", 7) == 0) {
        char *host_start = url + 7; 
        char *path_start = strchr(host_start, '/');
        if (path_start != NULL) {
            *path_start = '\0'; // Null-terminate
        }
        char *port_start = strchr(host_start, ':'); 
        if (port_start != NULL) {
            *port_start = '\0'; 
            sscanf(port_start + 1, "%5s", port);
        }
        sscanf(host_start, "%[^:/]", host);
    } else {
        fprintf(stderr, "Unsupported URL format\n");
        close(client_socket);
        return NULL;
    }

    // Extract the path and query from the URL
    char *path_and_query = strchr(url + 7, '/');
    if (path_and_query == NULL) {
        path_and_query = "/";
    }

    // Concatenate the URL and path_and_query to form the complete request URL
    char complete_url[BUFFER_SIZE];
    snprintf(complete_url, BUFFER_SIZE, "%s%s", url, path_and_query);
    
    int status;
    // Check access control list
    if (check_access_control(host, forbidden_sites_file)) {
        response_size = send_403_response(client_socket);
        logging(access_log_file, first, 403, response_size);
        printf("Access to %s is forbidden\n", host);
        close(client_socket);
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
  
    char request[4096];
    
    if (strstr(method, "HEAD") != NULL) {
            // Prepare the request using the complete URL
        snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, complete_url, host);

       // printf("%s\n", request);
        // Forward request to destination server
        char *response = https_request(request, host, port, &response_size);
        if (response != NULL) {
            send(client_socket, response, strlen(response), 0);
            status = extract_status_code(response);
        }else{
            response_size = send_500_response(client_socket);
            logging(access_log_file, first, 500, response_size);
            close(client_socket);
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
    } else if (strstr(method, "GET") != NULL) {        
    // Prepare the request using the complete URL
        snprintf(request, BUFFER_SIZE, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, complete_url, host);

        // Forward request to destination server
        char *response = https_request(request, host, port, &response_size);
        if (response != NULL) {
            send(client_socket, response, strlen(response), 0);
            status = extract_status_code(response);
        }else{
            response_size = send_500_response(client_socket);
            logging(access_log_file, first, 500, response_size);
            close(client_socket);
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
        
    } else {
        char *not_implemented_response = "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/html\r\nContent-Length: 36\r\n\r\n<html><body><h1>501 Not Implemented</h1></body></html>";
        send(client_socket, not_implemented_response, strlen(not_implemented_response), 0);
        logging(access_log_file, first, 501, strlen(not_implemented_response));
        close(client_socket);
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
   // printf("%s\n", client_ip);
    logging(access_log_file, first, status, response_size);
    close(client_socket);
    pthread_mutex_unlock(&mutex);

    pthread_exit(NULL);
    return NULL;
}



int main(int argc, char *argv[]) {
    if (argc !=4) {
        fprintf(stderr, "Usage: %s listen_port forbidden_sites_file access_log_file\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int listen_port = atoi(argv[1]);
    char *forbidden_sites_file = argv[2];
    char *access_log_file = argv[3];

    signal(SIGINT, sigint_handler);

    // Create a socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the specified port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 10) < 0) {
        perror("Error listening");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d...\n", listen_port);

    while (1) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
            if (client_socket < 0) {
                perror("Error accepting connection");
                continue;
            }

            pthread_t thread;
            
            ClientInfo *client_info = malloc(sizeof(ClientInfo));
            if (client_info == NULL) {
                perror("Error allocating memory");
                close(client_socket);
                // pthread_mutex_unlock(&mutex);
                continue;
            }
            client_info->socket = client_socket;
            inet_ntop(AF_INET, &client_addr.sin_addr, client_info->ip, INET_ADDRSTRLEN);
            client_info->access_log_file = access_log_file;
            client_info->forbidden_sites_file = forbidden_sites_file;
            pthread_create(&thread, NULL, client_handler, (void *)client_info);
            
            pthread_detach(thread);
        }

    close(server_socket);
    return 0;
}
