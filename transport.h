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

#ifndef SIPSAK_TRANSPORT_H
#define SIPSAK_TRANSPORT_H

void create_sockets(struct sockaddr_in *adr, int usock, int csock);

void send_message(char* mes, struct sockaddr *dest, int usock, int csock, int dontsend);

void check_socket_error(int socket, int size);

int check_for_message(char *recv, int size);

int recv_message(char *buf, int size);

int set_target(struct sockaddr_in *adr, unsigned long target, int port, int socket, int connected);
#endif
