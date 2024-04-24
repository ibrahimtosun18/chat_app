#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 4096

// Function to initialize SSL context for secure communication
SSL_CTX* initialize_ssl_context() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, "/home/ibrahim/Desktop/SSL certificates/ca-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Thread function to continuously receive messages from the server
void *receive_message(void *ssl_conn) {
    SSL *ssl = (SSL *)ssl_conn;
    char buffer[BUFFER_SIZE];

    while (1) {
        int received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (received <= 0) {
            if (received == 0) {
                printf("Server closed the connection.\n");
            } else {
                perror("Receive failed");
            }
            break;
        }
        buffer[received] = '\0';
        printf("%s\n", buffer); // Print received message directly
    }

    return NULL;
}

int main() {
    // Initialize SSL context
    SSL_CTX *ctx = initialize_ssl_context();

    // Create a socket for communication
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connect failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL structure for the connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Send the client identifier to the server
    const char *client_id = "Client"; // You can change this to the desired client identifier
    SSL_write(ssl, client_id, strlen(client_id));

    // Create a new thread to receive messages from the server
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_message, ssl) != 0) {
        perror("Thread creation failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Main loop to send messages to the server
    printf("Enter 'exit' to quit or start typing messages.\n");
    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, stdin)) {
        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

        if (strcmp(buffer, "exit") == 0) break;

        if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
            perror("SSL Send failed");
            break;
        }
    }

    // Clean up before exiting
    pthread_cancel(recv_thread);
    pthread_join(recv_thread, NULL);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
