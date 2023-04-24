/*
 *  Cyber Laboratory Course Assignment 3
 *  Attack Header File
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

#ifndef _ATTACK_HDR_H
#define _ATTACK_HDR_H

#include <linux/ip.h>
#include <linux/tcp.h>

/*
 * @brief Log files name for the C mode.
 * @note The default value is "syns_results_c.txt".
*/
#define ATTK_LOG_FILE_C "syns_results_c.txt"

/*
 * @brief Log files name for the Python mode.
 * @note The default value is "syns_results_p.txt".
*/
#define ATTK_LOG_FILE_P "syns_results_p.txt"

/*
 * @brief Defines the invalid socket constant.
*/
#define INVALID_SOCKET      -1

/**********************************/
/******* IP Header settings *******/
/**********************************/

/* IP version */
/*
 * @brief Defines the IP version.
 * @note 4 is the only valid value.
*/
#define P_IP_VERSION                4

/*
 * @brief Defines the IP header length.
 * @note 5 is the only valid value.
*/
#define P_IP_HL                     5

/*
 * @brief Defines the IP header Time To Live.
 * @note Can be any value between 0 and 255, but 64 is the default.
*/
#define P_IP_TTL                    64


/***********************************/
/******* TCP Header settings *******/
/***********************************/

/* TCP packet source port. */
/*
 * @brief Defines the TCP packet source port.
 * @note Can be any value between 0 and 65535.
 * @note -1 means that the source port will be random.
*/
#define P_TCP_SPORT                 -1

/* TCP packet destenation port. */
/*
 * @brief Defines the TCP packet destination port.
 * @note Can be any value between 0 and 65535.
*/
#define P_TCP_DPORT                 80

/*
 * @brief Defines the TCP packet sequence number.
 * @note Can be any value between 0 and 4294967295.
 * @note -1 means that the sequence number will be random.
*/
#define P_TCP_SEQ                   -1

/*
 * @brief Defines the TCP packet acknowledgement number.
 * @note Can be any value between 0 and 4294967295.
 * @note -1 means that the acknowledgement number will be random.
*/
#define P_TCP_ACKSEQ                -1

/*
 * @brief Defines the TCP header length.
 * @note 5 is the only valid value.
*/
#define P_TCP_HL                    5

/*
 * @brief Defines the TCP packet window size.
 * @note Can be any value between 0 and 65535.
 * @note -1 means that the window size will be random.
*/
#define P_TCP_WIN                   -1

/*
 * @brief A struct that represents the pseudo TCP header.
 * @note The struct is used to calculate the TCP checksum, and isn't
 *          intended to be used as a real TCP header.
 * @note The struct is based on the pseudo TCP header struct from the
 *         following link: https://www.binarytides.com/raw-sockets-c-code-linux/
*/
struct pseudo_tcp
{
    // The source IP address.
    u_int32_t saddr;

    // The destination IP address.
    u_int32_t daddr;

    // The mbz field (always 0 by definition).
    u_int8_t mbz;

    // The protocol field (always 6 by definition).
    u_int8_t ptcl;

    // The TCP header length.
    u_int16_t tcpl;

    // The real TCP header itself.
    struct tcphdr tcp;
};

/*
 * @brief Sends a raw IP packet.
 * @param iph The IP header to send.
 * @note The function does not return a value.
*/
void send_raw_ip_packet(struct iphdr *iph);

/*
 * @brief Calculates the IP header checksum.
 * @param iph The IP header to calculate the checksum for.
 * @return The calculated checksum.
*/
unsigned short in_cksum(unsigned short *buf, int length);

/*
 * @brief Calculates the TCP header checksum.
 * @param iph The IP header to calculate the checksum for.
 * @return The calculated checksum.
 * @note The function uses the pseudo TCP header struct.
 * @note The functioN uses the in_cksum function.
*/
unsigned short calculate_tcp_checksum(struct iphdr *iph);

#endif