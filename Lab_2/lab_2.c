#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

const int MAX_CLIENTS = 1;
const int LISTEN_PORT = 1337;

// Signal variable, can be changed by external events
volatile sig_atomic_t wasSignal = 0;


typedef struct {
    int connfd;
    struct sockaddr_in addr;
} client_t;


void signalHandler(int r){
    wasSignal = 1;
}


void printClientAdd(client_t *client) {
    printf("[%s:%d]", inet_ntoa(client->addr.sin_addr), htons(client->addr.sin_port));
}


// SIGHUP handler
void setupSignalHandler(sigset_t *origMask) {
    struct sigaction sa;
    sigaction(SIGHUP, NULL, &sa);
    sa.sa_handler = signalHandler;
    sa.sa_flags |= SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);

    sigset_t blockedMask;
    sigemptyset(&blockedMask);
    sigaddset (&blockedMask, SIGHUP);
    sigprocmask(SIG_BLOCK, &blockedMask, origMask);
}


// TCP Server
int create_server(int port) {
    int sockfd;
    struct sockaddr_in servaddr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        puts("Socket creation failed\n");
        exit(-1);
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if ((bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) {
        puts("Socket bind failed\n");
        exit(-1);
    }
    if ((listen(sockfd, MAX_CLIENTS)) != 0) {
        puts("Listen failed\n");
        exit(-1);
    }
    return sockfd;
}


// Driver code
int _main(int sockfd,  sigset_t origSigMask) {
    client_t clients[MAX_CLIENTS+1];
    int active_clients = 0;
    char buffer[1024] = {0};
     while(true) {

        // New client init
        if (wasSignal) {
            wasSignal = 0;
            puts("Clients: ");
            for (int i = 0; i < active_clients; i++) {
                printClientAdd(clients);
                puts(" ");
            }
            puts("\n");
        }

        // Link FD with socket
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        int maxFd = sockfd;

        for (int i = 0; i < active_clients; i++) {
            FD_SET(clients[i].connfd, &fds);
            if(clients[i].connfd > maxFd) {
                maxFd = clients[i].connfd;
            }
        }

        // Signal handling with race-safe pselect() call
        if (pselect (maxFd + 1, &fds, NULL, NULL, NULL, &origSigMask) < 0 ) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        // Connect client
        if (FD_ISSET(sockfd, &fds) && active_clients < MAX_CLIENTS) {
            client_t *client = &clients[active_clients];
            socklen_t len = sizeof(client->addr);
            int connfd = accept(sockfd, (struct sockaddr*)&client->addr, &len);
            if (connfd >= 0) {
                client->connfd = connfd;
                printClientAdd(client);
                puts(" Connected!\n");
                active_clients++;
            }
            else {
                printf("Accept error: %s\n", strerror(errno));
            }
        }

        // Read client data into buffer
        for (int i = 0; i < active_clients; i++) {
            client_t *client = &clients[i];
            if (FD_ISSET(client->connfd, &fds)) {
                int read_len = read(client->connfd, &buffer, 1023);
                if (read_len > 0) {
                    buffer[read_len - 1] = 0;
                    printClientAdd(client);
                    printf(" %s\n", buffer);
                }
                else {
                    close(client->connfd);
                    printClientAdd(client);
                    puts(" Connection closed\n");
                    clients[i] = clients[active_clients - 1];
                    active_clients--;
                    i--;
                }
            }
        }
    }
}

int main() {
    int sockfd = create_server(LISTEN_PORT);
    puts("Listening...\n");

    sigset_t origSigMask;
    setupSignalHandler(&origSigMask);

    int res = _main(sockfd, origSigMask);
    if (res == -1){
        puts("pselect failed\n");
    }
}
