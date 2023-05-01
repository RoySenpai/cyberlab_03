/*
 *  Cyber Laboratory Course Assignment 3
 *  Ping library file
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
#include <strings.h>
#include <unistd.h>
#include "ping_header.h"

int checkArguments(int argc, char** argv, struct sockaddr_in* dest_in, socklen_t* addr_len) {
    if (argc < 3)
    {
        printf("Usage: %s <IP address> [-cp]\n", *argv);
        return -1;
    }

    memset(dest_in, 0, sizeof(struct sockaddr_in));

    if (inet_pton(AF_INET, *(argv + 1), &(dest_in->sin_addr)) <= 0)
    {
        printf("Invalid IP address: %s\n", *(argv + 1));
        return -1;
    }

    dest_in->sin_family = AF_INET;
    *addr_len = sizeof(struct sockaddr_in);

    if (strcmp(*(argv + 2), "-c") == 0)
        return 1;

    else if (strcmp(*(argv + 2), "-p") == 0)
        return 2;

    printf("Invalid argument: %s\n", *(argv + 2));
    
    return -1;
}

int setupRawSocket(struct icmphdr *icmphdr, int id) {
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        fprintf(stderr, "Socket error: %s\n", strerror(errno));
        return -1;
    }

    icmphdr->type = ICMP_ECHO;
    icmphdr->code = 0;
    icmphdr->un.echo.id = id;
    icmphdr->un.echo.sequence = 0;

    return sockfd;
}

void preparePing(char *packet, struct icmphdr *icmphdr, char *data, size_t datalen) {
    static uint16_t seq = 0;

    bzero(packet, sizeof(struct icmphdr) + datalen);

    icmphdr->un.echo.sequence = htons(++seq);
    icmphdr->checksum = 0;

    memcpy((packet), icmphdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    icmphdr->checksum = calculate_checksum((unsigned short *)packet, sizeof(struct icmphdr) + datalen);

    memcpy(packet, icmphdr, sizeof(struct icmphdr));
}

unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

ssize_t sendICMPpacket(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len) {
    ssize_t n;

    if ((n = sendto(socketfd, packet, sizeof(struct icmphdr) + datalen, 0, (struct sockaddr *)dest_in, len)) < 0)
    {
        fprintf(stderr, "Sendto error: %s\n", strerror(errno));
        return -1;
    }

    return n;
}

ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len) {
    ssize_t n;

    if ((n = recvfrom(socketfd, response, response_len, 0, (struct sockaddr *)dest_in, len)) < 0)
    {
        fprintf(stderr, "Recvfrom error: %s\n", strerror(errno));
        return -1;
    }

    return n;
}