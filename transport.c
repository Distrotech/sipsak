/*
 * $Id$
 *
 * Copyright (C) 2005 Nils Ohlmeier
 *
 * This file belongs to sipsak, a free sip testing tool.
 *
 * sipsak is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * sipsak is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "sipsak.h"

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif /* TIME_WITH_SYS_TIME */
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "shoot.h"

#ifdef RAW_SUPPORT
# ifdef HAVE_NETINET_IN_SYSTM_H 
#  include <netinet/in_systm.h>
# endif
# ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
# endif
# ifdef HAVE_NETINET_IP_ICMP_H
#  include <netinet/ip_icmp.h>
# endif
# ifdef HAVE_NETINET_UDP_H
#  define __FAVOR_BSD
#  include <netinet/udp.h>
# endif
#endif /* RAW_SUPPORT */

#include "exit_code.h"
#include "helper.h"

#ifdef RAW_SUPPORT
int rawsock;
#endif

void create_sockets(struct sockaddr_in *adr, int usock, int csock) {
	socklen_t slen;

	if (transport == SIP_UDP_TRANSPORT) {
		/* create the un-connected socket */
		if (!symmetric) {
			usock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (usock==-1) {
				perror("unconnected UDP socket creation failed");
				exit_code(2);
			}
			if (bind(usock, (struct sockaddr *) adr, sizeof(struct sockaddr_in) )==-1) {
				perror("unconnected UDP socket binding failed");
				exit_code(2);
			}
		}


#ifdef RAW_SUPPORT
		/* try to create the raw socket */
		rawsock = (int)socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (rawsock==-1) {
			if (verbose>0)
				fprintf(stderr, "warning: need raw socket (root privileges) to receive all ICMP errors\n");
#endif
			/* create the connected socket as a primitve alternative to the 
			   raw socket*/
			csock = (int)socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (csock==-1) {
				perror("connected UDP socket creation failed");
				exit_code(2);
			}

			if (!symmetric)
				adr->sin_port = htons((short)0);
			if (bind(csock, (struct sockaddr *) adr, sizeof(struct sockaddr_in) )==-1) {
				perror("connected UDP socket binding failed");
				exit_code(2);
			}
#ifdef RAW_SUPPORT
		}
#endif
	}
	else {
		csock = (int)socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (csock==-1) {
			perror("TCP socket creation failed");
			exit_code(2);
		}
		if (bind(csock, (struct sockaddr *) adr, sizeof(struct sockaddr_in) )==-1) {
			perror("TCP socket binding failed");
			exit_code(2);
		}
	}

	/* for the via line we need our listening port number */
	if (lport==0){
		memset(adr, 0, sizeof(struct sockaddr_in));
		slen=sizeof(struct sockaddr_in);
		if (symmetric || transport != SIP_UDP_TRANSPORT)
			getsockname(csock, (struct sockaddr *)adr, &slen);
		else
			getsockname(usock, (struct sockaddr *)adr, &slen);
		lport=ntohs(adr->sin_port);
	}
}

void send_message(char* mes, struct sockaddr *dest, int usock, int csock, 
			int *dontsend, struct timeval *sendtime, struct timezone *tz, int *send_counter) {
	int ret;

	if (dontsend == 0) {
		if (verbose > 2) {
			printf("\nrequest:\n%s", mes);
		}
		/* lets fire the request to the server and store when we did */
		if (csock == -1) {
			ret = sendto(usock, mes, strlen(mes), 0, dest, sizeof(struct sockaddr));
		}
		else {
			ret = send(csock, mes, strlen(mes), 0);
		}
		(void)gettimeofday(sendtime, tz);
		if (ret==-1) {
			printf("\n");
			perror("send failure");
			exit_code(2);
		}
#ifdef HAVE_INET_NTOP
		if (verbose > 2) {
			printf("\nsend to: %s:%s:%i\n", transport_str, target_dot, rport);
    }
#endif
		send_counter++;
	}
	else {
		dontsend = 0;
	}
}

void check_socket_error(int socket, int size) {
	struct pollfd sockerr;
	int ret = 0;

	/* lets see if we at least received an icmp error */
	sockerr.fd=socket;
	sockerr.events=POLLERR;
	ret = poll(&sockerr, 1, 10);
	if (ret==1) {
		if (sockerr.revents && POLLERR) {
			recvfrom(socket, recv, size, 0, NULL, 0);
			printf("\n");
			perror("send failure");
			if (randtrash == 1) 
				printf ("last message before send failure:\n%s\n", req);
			exit_code(3);
		}
	}
}

int check_for_message(char *recv, int size, int *dontrecv,
				struct timeval *tv, int *retryAfter, int usock, int csock,
				struct timeval *recvtime, struct timezone *tz, int send_counter,
				struct timeval *firstsendt, struct timeval *sendtime,
				struct timeval *starttime, int *randretrys, double *senddiff,
				int inv_trans, int *retrans_s_c, struct timeval *delaytime) {
	fd_set	fd;
	int ret = 0;

	if (dontrecv == 0) {
		/* set the timeout and wait for a response */
		tv->tv_sec = *retryAfter/1000;
		tv->tv_usec = (*retryAfter % 1000) * 1000;

		FD_ZERO(&fd);
		if (usock != -1)
			FD_SET(usock, &fd); 
		if (csock != -1)
			FD_SET(csock, &fd); 
#ifdef RAW_SUPPORT
		if (rawsock != -1)
			FD_SET(rawsock, &fd); 
#endif

		ret = select(FD_SETSIZE, &fd, NULL, NULL, tv);
		(void)gettimeofday(recvtime, tz);
	}
	else {
		dontrecv = 0;
	}

	/* store the time of our first send */
	if (send_counter==1) {
		memcpy(firstsendt, sendtime, sizeof(struct timeval));
	}
	if (*retryAfter == SIP_T1) {
		memcpy(starttime, sendtime, sizeof(struct timeval));
	}
	if (ret == 0)
	{
		/* lets see if we at least received an icmp error */
		if (csock == -1) 
			check_socket_error(usock, size);
		else
			check_socket_error(csock, size);
		/* printout that we did not received anything */
		if (trace == 1) {
			printf("%i: timeout after %i ms\n", namebeg, *retryAfter);
		}
		else if (usrloc == 1||invite == 1||message == 1) {
			printf("timeout after %i ms\n", *retryAfter);
		}
		else if (verbose>0) 
			printf("** timeout after %i ms**\n", *retryAfter);
		if (randtrash == 1) {
			printf("did not get a response on this request:\n%s\n", req);
			if (cseq_counter < nameend) {
				if (*randretrys == 2) {
					printf("sended the following message three "
							"times without getting a response:\n%s\n"
							"give up further retransmissions...\n", req);
					exit_code(3);
				}
				else {
					printf("resending it without additional "
							"random changes...\n\n");
					randretrys++;
				}
			}
		}
		*senddiff = deltaT(starttime, recvtime);
		if (*senddiff > (float)64 * (float)SIP_T1) {
			if (verbose>0)
				printf("*** giving up, no final response after %.3f ms\n", *senddiff);
			exit_code(3);
		}
		/* set retry time according to RFC3261 */
		if ((inv_trans) || (*retryAfter *2 < SIP_T2)) {
			*retryAfter = *retryAfter * 2;
		}
		else {
			*retryAfter = SIP_T2;
		}
		retrans_s_c++;
		if (delaytime->tv_sec == 0)
			memcpy(&delaytime, &sendtime, sizeof(struct timeval));
		/* if we did not exit until here lets try another send */
		return -1;
	}
	else if ( ret == -1 ) {
		perror("select error");
		exit_code(2);
	}
	else if (((usock != -1) && FD_ISSET(usock, &fd)) || ((csock != -1) && FD_ISSET(csock, &fd))) {
		if ((usock != -1) && FD_ISSET(usock, &fd))
			ret = usock;
		else if ((csock != -1) && FD_ISSET(csock, &fd))
			ret = csock;
		else {
			printf("unable to determine the socket which received something\n");
			exit_code(2);
		}
		/* no timeout, no error ... something has happened :-) */
	 	if (trace == 0 && usrloc ==0 && invite == 0 && message == 0 && randtrash == 0 && (verbose > 1))
			printf ("\nmessage received");
	}
#ifdef RAW_SUPPORT
	else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
		if (verbose > 1)
			printf("\nreceived ICMP packet");
		ret = rawsock;
	}
#endif
	else {
		printf("\nselect returned succesfuly, nothing received\n");
		return -1;
	}
	return ret;
}

int recv_message(char *buf, int size, int inv_trans, int *retryAfter,
					struct timeval *delaytime, struct timeval *recvtime,
					double *big_delay) {
	int ret = 0;
	int sock = 0;
	double tmp_delay;
#ifdef HAVE_INET_NTOP
	struct sockaddr_in peer_adr;
	socklen_t psize = sizeof(peer_adr);
#endif
#ifdef RAW_SUPPORT
	struct sockaddr_in faddr;
	struct ip 		*r_ip_hdr, *s_ip_hdr;
	struct icmp 	*icmp_hdr;
	struct udphdr 	*udp_hdr;
	size_t r_ip_len, s_ip_len, icmp_len;
	int srcport, dstport;
	unsigned int flen;
#endif

	sock = check_for_message(buf, size);
	if (sock <= 1) {
		return -1;
	}
	if (sock != rawsock) {
		check_socket_error(sock, size);
		ret = recvfrom(sock, buf, size, 0, NULL, 0);
	}
#ifdef RAW_SUPPORT
	else {
		/* lets check if the ICMP message matches with our 
		   sent packet */
		flen = sizeof(faddr);
		memset(&faddr, 0, sizeof(struct sockaddr));
		ret = recvfrom(rawsock, buf, size, 0, (struct sockaddr *)&faddr, &flen);
		if (ret == -1) {
			perror("error while trying to read from icmp raw socket");
			exit_code(2);
		}
		r_ip_hdr = (struct ip *) buf;
		r_ip_len = r_ip_hdr->ip_hl << 2;

		icmp_hdr = (struct icmp *) (buf + r_ip_len);
		icmp_len = ret - r_ip_len;

		if (icmp_len < 8) {
			if (verbose > 1)
				printf(": ignoring (ICMP header length below 8 bytes)\n");
			return -2;
		}
		else if (icmp_len < 36) {
			if (verbose > 1)
				printf(": ignoring (ICMP message too short to contain IP and UDP header)\n");
			return -2;
		}
		s_ip_hdr = (struct ip *) ((char *)icmp_hdr + 8);
		s_ip_len = s_ip_hdr->ip_hl << 2;
		if (s_ip_hdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *) ((char *)s_ip_hdr + s_ip_len);
			srcport = ntohs(udp_hdr->uh_sport);
			dstport = ntohs(udp_hdr->uh_dport);
			if ((srcport == lport) && (dstport == rport)) {
				printf(" (type: %u, code: %u)", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
#ifdef HAVE_INET_NTOP
				if (inet_ntop(AF_INET, &faddr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)
					printf(": from %s\n", source_dot);
				else
					printf("\n");
#else
				printf("\n");
#endif
				exit_code(3);
			}
			else {
				if (verbose > 2)
					printf(": ignoring (ICMP error does not match send data)\n");
				return -2;
			}
		}
		else {
			if (verbose > 1)
				printf(": ignoring (ICMP data is not a UDP packet)\n");
			return -2;
		}
	}
#endif
	if (ret > 0) {
		*(buf+ ret) = '\0';
		if (!inv_trans && (regexec(&proexp, rec, 0, 0, 0) != REG_NOERROR)) {
			*retryAfter = SIP_T1;
		}
		/* store the biggest delay if one occured */
		if (delaytime->tv_sec != 0) {
			tmp_delay = deltaT(delaytime, recvtime);
			if (tmp_delay > *big_delay)
				*big_delay = tmp_delay;
			delaytime->tv_sec = 0;
			delaytime->tv_usec = 0;
		}
#ifdef HAVE_INET_NTOP
		if ((verbose > 2) && (getpeername(sock, (struct sockaddr *)&peer_adr, &psize) == 0) && (inet_ntop(peer_adr.sin_family, &peer_adr.sin_addr, &source_dot[0], INET_ADDRSTRLEN) != NULL)) {
			printf("\nreceived from: %s:%s:%i\n", transport_str, 
						source_dot, ntohs(peer_adr.sin_port));
		}
		else if (verbose > 1 && trace == 0 && usrloc == 0)
			printf(":\n");
#else
		if (trace == 0 && usrloc == 0)
			printf(":\n");
#endif
	}
	else {
		check_socket_error(sock, size);
		printf("nothing received, select returned error\n");
		exit_code(2);
	}
	return ret;
}

/* clears the given sockaddr, fills it with the given data and if a
 * socket is given connects the socket to the new target */
int set_target(struct sockaddr_in *adr, unsigned long target, int port, int socket, int connected)
{
	if (socket != -1 && transport != SIP_UDP_TRANSPORT && connected) {
		if (shutdown(socket, SHUT_RDWR) != 0) {
			perror("error while shutting down socket");
		}
	}

	memset(adr, 0, sizeof(struct sockaddr_in));
	adr->sin_addr.s_addr = target;
	adr->sin_port = htons((short)port);
	adr->sin_family = AF_INET;

#ifdef HAVE_INET_NTOP
	inet_ntop(adr->sin_family, &adr->sin_addr, &target_dot[0], INET_ADDRSTRLEN);
#endif

	if (socket != -1) {
		if (connect(socket, (struct sockaddr *)adr, sizeof(struct sockaddr_in)) == -1) {
			perror("connecting socket failed");
			exit_code(2);
		}
	}
	return 1;
}

