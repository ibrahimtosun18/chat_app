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

typedef struct {
    int socket;
    SSL *ssl;
    char identifier[50];  // Buffer to store the client's identifier
} client_t;

client_t *clients[MAX_CLIENTS];
int n_clients = 0;

void broadcast_message(const char *message, int sender_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < n_clients; i++) {
        if (clients[i]->socket != sender_socket) {
            SSL_write(clients[i]->ssl, message, strlen(message));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

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

    while ((bytes_read = SSL_read(client->ssl, buffer, sizeof(buffer)-1)) > 0) {
        buffer[bytes_read] = '\0';
        char full_message[BUFFER_SIZE];
        int ret = snprintf(full_message, sizeof(full_message), "%s: %s", client->identifier, buffer);
        if (ret >= BUFFER_SIZE) {
            // Handle truncation
            fprintf(stderr, "Message truncated. Increase BUFFER_SIZE to accommodate larger messages.\n");
        }
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
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "/home/ibrahim/Desktop/SSL certificates/server-cert.pem", SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, "/home/ibrahim/Desktop/SSL certificates/server-key.pem", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Failed to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int client_fd = accept(server_fd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        client_t *new_client = (client_t*)malloc(sizeof(client_t));
        new_client->socket = client_fd;
        new_client->ssl = ssl;
        snprintf(new_client->identifier, sizeof(new_client->identifier), "Client%d", client_fd);  // Assign identifier based on socket fd
        add_client(new_client);

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

    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}
