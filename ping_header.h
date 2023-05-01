/*
 *  Cyber Laboratory Course Assignment 3
 *  Ping header program
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

#ifndef _PING_HDR_H
#define _PING_HDR_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

/*
 * @brief Defines the invalid socket constant.
*/
#define INVALID_SOCKET      -1

/*
 * @brief Defines the length of the ICMP header.
 * @note The default value is 8 bytes.
*/
#define ICMP_HDRLEN         8

/*
 * @brief Defines the length of the ICMP ECHO REQUEST packet.
 * @note The default value is 32 bytes.
*/
#define ICMP_ECHO_MSG_LEN   32

/*
 * @brief Defines the wait time in ms after receiving an ICMP ECHO REPLAY packet.
 * @note This is used to prevent the program from sending too many ICMP ECHO REQUEST packets.
 * @note The value is in seconds.
 * @note The default value is 5 seconds.
*/
#define PING_WAIT_TIME      5

/*
 * @brief Log files name for the C mode.
 * @note The default value is "pings_results_c.txt".
*/
#define PING_LOG_FILE_C "pings_results_c.txt"

/*
 * @brief Log files name for the Python mode.
 * @note The default value is "pings_results_p.txt".
*/
#define PING_LOG_FILE_P "pings_results_p.txt"

/*
 * @brief Checks the arguments given to the program.
 * @param argc The number of arguments given to the program.
 * @param argv The arguments given to the program.
 * @param dest_in The destination address.
 * @param addr_len The length of the destination address.
 * @return -1 if an error occurred, 1 if the -c argument (c mode) was given, 2 if the -p argument (python mode) was given.
*/
int checkArguments(int argc, char** argv, struct sockaddr_in* dest_in, socklen_t* addr_len);

/*
 * @brief Sets up the raw socket.
 * @param icmphdr The ICMP header.
 * @param id The ID of the ICMP ECHO REQUEST packet.
 * @return The socket file descriptor.
*/
int setupRawSocket(struct icmphdr *icmphdr, int id);

/*
 * @brief Prepares the ICMP ECHO REQUEST packet.
 * @param packet The packet to prepare.
 * @param icmphdr The ICMP header.
 * @param data The data to send.
 * @param datalen The length of the data to send.
 * @return (void) nothing.
*/
void preparePing(char *packet, struct icmphdr *icmphdr, char *data, size_t datalen);

/*
 * @brief Calculates the checksum of the packet.
 * @param paddress The address of the packet.
 * @param len The length of the packet.
 * @return The checksum of the packet.
*/
unsigned short calculate_checksum(unsigned short *paddress, int len);

/*
 * @brief Sends the ICMP ECHO REQUEST packet.
 * @param socketfd The socket file descriptor.
 * @param packet The packet to send.
 * @param datalen The length of the packet to send.
 * @param dest_in The destination address.
 * @param len The length of the destination address.
 * @return The number of bytes sent.
*/
ssize_t sendICMPpacket(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len);

/*
 * @brief Receives the ICMP ECHO REPLAY packet.
 * @param socketfd The socket file descriptor.
 * @param response The response to receive.
 * @param response_len The length of the response to receive.
 * @param dest_in The destination address.
 * @param len The length of the destination address.
 * @return The number of bytes received.
*/
ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len);

#endif