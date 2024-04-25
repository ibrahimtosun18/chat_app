#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 8192  // Increased buffer size

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Structure to hold client information
typedef struct {
    int socket;
    SSL *ssl;
    char identifier[50];  // Buffer to store the client's identifier
} client_t;

client_t *clients[MAX_CLIENTS];
int n_clients = 0;

// Function to broadcast messages to all clients except the sender
void broadcast_message(const char *message, int sender_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < n_clients; i++) {
        if (clients[i]->socket != sender_socket) {
            SSL_write(clients[i]->ssl, message, strlen(message));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to add a new client to the client list
void add_client(client_t *cl) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = cl;
            n_clients++;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to remove a client from the client list
void remove_client(int socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket == socket) {
            clients[i] = NULL;
            n_clients--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}
void* handle_client(void* arg) {
    client_t *client = (client_t*)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // First, read the client's identifier
    bytes_read = SSL_read(client->ssl, client->identifier, sizeof(client->identifier)-1);
    if (bytes_read > 0) {
        client->identifier[bytes_read] = '\0'; // Ensure null termination
    } else {
        // If we cannot read the identifier, clean up and exit this client's thread
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        close(client->socket);
        remove_client(client->socket);
        free(client);
        return NULL;
    }

    // Now proceed with the regular message handling
    while ((bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer)-1)) > 0) {
        buffer[bytes_read] = '\0';
        char full_message[8500]; // Increased buffer size to accommodate potential truncation
        snprintf(full_message, sizeof(full_message), "%s: %s", client->identifier, buffer);
        broadcast_message(full_message, client->socket);
    }

    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    close(client->socket);
    remove_client(client->socket);
    free(client);
    return NULL;
}

int main() {
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "/home/ibrahim/Desktop/SSL certificates/server-cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "/home/ibrahim/Desktop/SSL certificates/server-key.pem", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Create a socket for communication
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the server address
    if (bind(server_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 10) < 0) {
        perror("Failed to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    // Accept and handle incoming connections
    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int client_fd = accept(server_fd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        // Create SSL structure for the connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // Allocate memory for client structure and initialize it
        client_t *new_client = (client_t*)malloc(sizeof(client_t));
        new_client->socket = client_fd;
        new_client->ssl = ssl;

        // Send a prompt to the client requesting their name
        const char *name_prompt = "Please enter your name: ";
        SSL_write(ssl, name_prompt, strlen(name_prompt));

        // Read the client's name
        int bytes_read = SSL_read(ssl, new_client->identifier, sizeof(new_client->identifier) - 1);
        if (bytes_read > 0) {
            new_client->identifier[bytes_read] = '\0'; // Ensure null termination
        } else {
            // If we cannot read the name, clean up and exit this client's thread
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            free(new_client);
            continue;
        }

        // Add the new client to the client list
        add_client(new_client);

        // Create a new thread to handle communication with the client
        pthread_t thread_tid;
        if (pthread_create(&thread_tid, NULL, handle_client, new_client) != 0) {
            perror("Thread creation failed");
            SSL_free(ssl);
            close(client_fd);
            free(new_client);
        } else {
            pthread_detach(thread_tid);
        }
    }

    // Clean up before exiting
    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
