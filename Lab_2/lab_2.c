#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

const int MAX_CLIENTS = 2;

volatile sig_atomic_t signalFlag = 0;

typedef struct {
    int socket;
    struct sockaddr_in addr;
} client_t;

void printClientInfo(client_t *client){
    printf("[%s:%d]", inet_ntoa(client->addr.sin_addr), htons(client->addr.sin_port));
}

void handleSigHup(int signal) {
    signalFlag = 1;
}

void configureSignalHandler(sigset_t *prevMask) {
    struct sigaction sa;
    sigaction(SIGHUP, NULL, &sa);
    // Set handler func
    sa.sa_handler = handleSigHup;
    sa.sa_flags |= SA_RESTART; 
    sigaction(SIGHUP, &sa, NULL);

    // Blocking SIGHUP
    sigset_t blockedMask;
    sigemptyset(&blockedMask);
    sigaddset(&blockedMask, SIGHUP);
    sigprocmask(SIG_BLOCK, &blockedMask, prevMask);
}

// TCP-server initialization
int initializeServer(int port) {
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("Socket creation error!");
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        perror("Socket binding error!");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, MAX_CLIENTS) != 0) {
        perror("Socket listening error!");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    return serverSocket;
}

int handleServerConnections(int serverSocket, sigset_t prevSignalMask) {
    client_t clients[MAX_CLIENTS];
    int clientCount = 0;
    char messageBuffer[1024] = {0};

    while (1) {
        // SIGHUP catch
        if (signalFlag) {
	        puts("Signal received!");
            signalFlag = 0;
        }

        // Preparing descriptors for pselect()
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        int maxFd = serverSocket;

        // Adding clients' descriptors
        for (int i = 0; i < clientCount; i++) {
            FD_SET(clients[i].socket, &readfds);
            if (clients[i].socket > maxFd) {
                maxFd = clients[i].socket;
            }
        }

        // Waiting for events
        if (pselect(maxFd + 1, &readfds, NULL, NULL, NULL, &prevSignalMask) == -1) {
            // Ignore signals interruption
            if (errno == EINTR) continue;
            return -1;
        }

        // New client handling
        if (FD_ISSET(serverSocket, &readfds) && clientCount < MAX_CLIENTS) {
            client_t *client = &clients[clientCount];
            socklen_t addrLen = sizeof(client->addr);
            int newSocket = accept(serverSocket, (struct sockaddr*)&client->addr, &addrLen);
            if (newSocket >= 0) {
                printClientInfo(client);
                puts(" connected!");
                client->socket = newSocket;
                clientCount++;
            } else {
                perror("accept() error!");
            }
        }

        // Read from client
        for (int i = 0; i < clientCount; i++) {
            client_t *client = &clients[i];
            if (FD_ISSET(client->socket, &readfds)) {
                int bytesRead = read(client->socket, messageBuffer, sizeof(messageBuffer) - 1);
                if (bytesRead > 0) {
                    // Terminate string
                    messageBuffer[bytesRead] = '\0';
                    printClientInfo(client);
                    printf(" said: %s", messageBuffer);
                } else {
                    close(client->socket);
                    printClientInfo(client);
                    puts(" closed!");
                    clients[i] = clients[clientCount - 1];
                    clientCount--;
                    i--;
                }
            }
        }
    }
}

int main() {
    int serverSocket = initializeServer(1488);
    puts("TCP server up!");

    sigset_t prevSignalMask;
    configureSignalHandler(&prevSignalMask);

    int result = handleServerConnections(serverSocket, prevSignalMask);
    if (result == -1) {
        perror("pselect() error!");
    }

    return 0;
}
