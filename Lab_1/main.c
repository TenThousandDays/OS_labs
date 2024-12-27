#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int ready = 0;

// Producer thread
void* producer(void *arg) {
    while (1) {
        pthread_mutex_lock(&lock);

        // Check flag to avoid event doubling
        if (ready == 1) {
            pthread_mutex_unlock(&lock);
            continue;
        }

        ready = 1;
        printf("msg SENT\n");

        // wake-up call
        pthread_cond_signal(&cond);

        pthread_mutex_unlock(&lock);

        // delay
        sleep(1);
    }
    return NULL;
}

// Consumer thread
void* consumer(void *arg) {
    while (1) {
        pthread_mutex_lock(&lock);

        // Waiting for event
        while (ready == 0) {
            pthread_cond_wait(&cond, &lock);
        }

        ready = 0;
	printf("msg RCV\n");

        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main() {
    pthread_t producer_thread, consumer_thread;

    pthread_create(&producer_thread, NULL, producer, NULL);
    pthread_create(&consumer_thread, NULL, consumer, NULL);

    // Wait for thread termination (infinite)
    pthread_join(producer_thread, NULL);
    pthread_join(consumer_thread, NULL);

    return 0;
}
