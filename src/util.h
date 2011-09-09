/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 * 
 */ 

#ifndef UTIL_H
	
	#define UTIL_H
	
	#include <stdint.h>
	#include <stdio.h>
	#include <errno.h>
	#include <stdlib.h>
	#include <unistd.h>
	#include <string.h>

	#define private static
	#define loop for(;;)

	typedef unsigned int uint;
	typedef unsigned long ulong;
	typedef int8_t byte;
	typedef uint8_t ubyte;
	typedef unsigned char uchar;
	typedef unsigned char bool;

	#define false 0
	#define true 1

	size_t writen(int fd, ubyte* buf, size_t n);
	size_t readn(int fd, ubyte* ptr, size_t nbytes);

	char* strappend(char* a, char* b);

#endif
