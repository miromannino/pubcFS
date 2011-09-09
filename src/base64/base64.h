/**
 * @file base64.h
 * @brief encoding and decoding algorithms for base64 and base64url
*/
/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 * 
 */ 

#ifndef BASE64_H
	
	#define BASE64_H
	
	#include <stdlib.h>
	#include <util.h> 
	#include <math.h> 
 
	/** Typedef of the variable that will contain the encoding and decoding options. */
	typedef uchar base64_opt_t;
	
	/** Empty option, default value with the standard alphabet and with no line wrapping */
	# define base64_OPT_EMPTY 0x00
	
	/** For the alternative alphabet (base64url) */
	# define base64_OPT_FILENAMESAFE 0x01
	
	/** For the line wrapping */
	# define base64_OPT_LINEWRAPPING 0x02
	
	/** If line wrapping enabled the lines will be with this size */
	#define base64_LINE_LENGTH 64 //IT MUST BE A MULTIPLE OF 4
	
	/** For decode a base64 string. */
	bool base64_decode(uchar* in, ubyte** out, size_t len_in, size_t* len_out, base64_opt_t opt);
	
	/** For encode a binary string to a readable string.  */
	bool base64_encode(ubyte* in, uchar** out, size_t len_in, size_t* len_out, base64_opt_t opt);
	
#endif
