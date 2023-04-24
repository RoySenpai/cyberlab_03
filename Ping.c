/*
 *  Cyber Laboratory Course Assignment 3
 *  Ping program
 *  Copyright (C) 2023  Roy Simanovich and Lidor Keren Yehushua
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "ping_header.h"

FILE* logFile;

/*
 * @brief Signal handler
 * @param signal Signal number
 * @return (void) None.
 * @note Used to clean up resources.
*/
void signalHandler() {
    if (logFile != NULL) {
        fclose(logFile);
    }

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    // Varibles setup
    struct icmphdr icmph;
    struct iphdr *iphdr_res;
    struct icmphdr *icmphdr_res;
    struct sockaddr_in dest_in;
    struct timeval start, end;

    socklen_t addr_len;
    ssize_t bytes_received = 0;
    size_t datalen;

    int socketfd = INVALID_SOCKET, mode = -1;

    double pingPongTime = 0.0;

    char packet[IP_MAXPACKET], response[IP_MAXPACKET], data[ICMP_ECHO_MSG_LEN], responseAddr[INET_ADDRSTRLEN];

    for (int i = 0; i < ICMP_ECHO_MSG_LEN - 1; i++)
        data[i] = 'a';

    data[ICMP_ECHO_MSG_LEN - 1] = '\0';
    datalen = (strlen(data) + 1);

    if ((mode = checkArguments(argc, argv, &dest_in, &addr_len)) == -1)
        return EXIT_FAILURE;

    logFile = fopen((mode == 1 ? PING_LOG_FILE_C:PING_LOG_FILE_P), "w");

    if (logFile == NULL)
    {
        fprintf(stderr, "Error opening log file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Setup signal handler
    if (signal(SIGINT, signalHandler) == SIG_ERR || signal(SIGTERM, signalHandler) == SIG_ERR)
    {
        fprintf(stderr, "Signal error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Check arguments
    if (checkArguments(argc, argv, &dest_in, &addr_len) == -1)
        return EXIT_FAILURE;

    // Setup raw socket
    if ((socketfd = setupRawSocket(&icmph, getpid())) < 0)
        return EXIT_FAILURE;

    // Setup ICMP header
    setupRawSocket(&icmph, getpid());

    fprintf(stdout, "PING %s (%s) %d bytes of data.\n", *(argv + 1), inet_ntoa(dest_in.sin_addr), ICMP_ECHO_MSG_LEN);
    
    while(1)
    {
        preparePing(packet, &icmph, data, datalen);

        gettimeofday(&start, NULL);

        if (sendICMPpacket(socketfd, packet, datalen, &dest_in, sizeof(dest_in)) < 0)
            return EXIT_FAILURE;

        bytes_received = receiveICMPpacket(socketfd, response, IP_MAXPACKET, &dest_in, &addr_len);

        if (bytes_received < 0)
            return EXIT_FAILURE;

        gettimeofday(&end, NULL);

        pingPongTime = ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_usec - start.tv_usec) / 1000.0);
        iphdr_res = (struct iphdr *)response;
        icmphdr_res = (struct icmphdr *)(response + iphdr_res->ihl*4);

        inet_ntop(AF_INET, &(iphdr_res->saddr), responseAddr, INET_ADDRSTRLEN);

        fprintf(logFile, "%d %0.3lf\n", ntohs(icmphdr_res->un.echo.sequence), pingPongTime);

        printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%0.3lf ms\n", 
        bytes_received, 
        responseAddr, 
        ntohs(icmphdr_res->un.echo.sequence),
        iphdr_res->ttl, 
        pingPongTime);

        sleep(5);
    }

    fclose(logFile);

    return EXIT_SUCCESS;
}