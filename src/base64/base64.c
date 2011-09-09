/**
 * @file base64.c
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

/*
 * For other information about Base64 visit:
 *	http://it.wikipedia.org/wiki/Base64
 * 
 * For a standard document about Base64:
 *  RFC 3548
 */
 
#include <base64.h>
 
private const uchar base64_alphabets[2][64] = {
		//RFC 3548 alphabet
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
		
		//RFC 3548 filename safe alphabet (or base64url)
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	};
	
private const ubyte base64_alphabets_reverse[2][256] = {
	{
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
	  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255,
	  255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
	  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255,
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
	},
	  
	{
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 
	  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255,
	  255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 
	  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 63, 
	  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 
	  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
	  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
	}
};
	
/** Decode a base64 string.
 * 
 * <b>Extraneous Symbols</b>
 * The base64 string can have extraneous symbols like CR, LF, SPACE... the parser skip the 
 * extraneous symbols. 
 * 
 * <b>Alphabets</b>
 * You can specify the base64 alphabet using the opt param
 * for specify that you want the traditional alphabet you just prepare opt like this
 * 		<code>
 * 			base64_opt_t opt;
 * 			opt = base64_OPT_EMPTY;
 * 		</code>
 * 
 * if you want use the url Base64 alphabet you just prepare opt like this
 * 		<code>
 * 			base64_opt_t opt;
 * 			opt = base64_OPT_EMPTY | base64_OPT_FILENAMESAFE;
 * 		</code>
 *  	
 * <b>Line wrapping</b>
 * the line wrapping in opt will be ignored because the behavior is the same (the extraneous 
 * symbols is skipped)
 * 
 * @param in the base64 string
 * @param out pointer to che ubyte* variable that will contain the string location of the decoded
 * 			  base64 string. The out is allocated with 'malloc' and it must be deallocate using
 * 			  the 'free' function.
 * @param len_in the length of the 'in' input param string.
 * @param len_out a pointer to the size_t variable that will contain the the length of the output
 * 			      string
 * @param opt the option (the line wrapping option will be ingored) 
 * 
 * @return if true the decode have success, false if the input string was corrupted or the malloc
 * 		   return NULL, if false no out was generated and no memory was allocated for the output
 * 		   in both cases.
 */
bool base64_decode(uchar* in, ubyte** out, size_t len_in, size_t* len_out, base64_opt_t opt)
{
	uchar in_block[4], in_valid[4], c;
	ubyte alphabet, *out_pos;
	size_t real_len_in, len_out_l;
	int i,j;

	alphabet = (opt & base64_OPT_FILENAMESAFE) ? 1 : 0;
	
	for(j = 0, real_len_in = 0, i = 0; i < len_in; i++){
		//we skip the exraneous symbols
		if(base64_alphabets_reverse[alphabet][in[i]] != 255){
		/*if((in[i] >= 'A' && in[i] <= 'Z') 
			|| (in[i] >= 'a' && in[i] <= 'z')
			|| (in[i] >= '0' && in[i] <= '9')
			|| (alphabet == 0 && (in[i] == '+' || in[i] == '/'))
			|| (alphabet == 1 && (in[i] == '-' || in[i] == '_'))
			|| (in[i] == '=')){*/
				
			in_valid[j] = in[i];
			if(j == 3) j = 0; else j++;
			real_len_in++;
		}
	}
	
	if (((real_len_in % 4) != 0) || (real_len_in == 0)) return false;
	len_out_l = real_len_in / 4 * 3;
	if(in_valid[2] == '=') len_out_l -= 2;
	else if(in_valid[3] == '=') len_out_l--;
	
	*out = out_pos = malloc(len_out_l);
	if (*out == NULL) return false;

	for(j = 0, i = 0; i < len_in; i++){
		/*if(in[i] >= 'A' && in[i] <= 'Z') c = in[i] - 'A';
		else if(in[i] >= 'a' && in[i] <= 'z') c = in[i] - 'a' + 26;
		else if(in[i] >= '0' && in[i] <= '9') c = in[i] - '0' + 52;
		else if(alphabet == 0 && in[i] == '+') c = 62;
		else if(alphabet == 0 && in[i] == '/') c = 63;
		else if(alphabet == 1 && in[i] == '-') c = 62;
		else if(alphabet == 1 && in[i] == '_') c = 63;
		else if(in[i] == '=') c = 0;
		else continue;*/
		c = base64_alphabets_reverse[alphabet][in[i]];
		if(c == 255) continue;
		
		//we must save in in_valid because we can't move back using in[] for the extraneous symbols
		in_valid[j] = in[i];
		
		in_block[j] = c;
		
		if(j == 3){
			if(in_valid[j-1] == '='){ //if there is two '='
				*out_pos = ((in_block[0] << 2) | (in_block[1] >> 4)); out_pos++;
			}else if(in_valid[j] == '='){ //if there is one '='
				*out_pos = ((in_block[0] << 2) | (in_block[1] >> 4)); out_pos++;
				*out_pos = ((in_block[1] << 4) | (in_block[2] >> 2)); out_pos++;
			}else{
				*out_pos = ((in_block[0] << 2) | (in_block[1] >> 4)); out_pos++;
				*out_pos = ((in_block[1] << 4) | (in_block[2] >> 2)); out_pos++;
				*out_pos = ((in_block[2] << 6) | (in_block[3])); out_pos++;
			}
			
			j = 0;
			
		}else{
			j++;
		}
		
	}
	
	*len_out = len_out_l;
	
	return true;
}

/** Encode a binary string to a readable string.
 * 
 * <b>Alphabets</b>
 * You can specify the base64 alphabet using the opt param
 * for specify that you want the traditional alphabet you just prepare opt like this
 * 		<code>
 * 			base64_opt_t opt;
 * 			opt = base64_OPT_EMPTY;
 * 		</code>
 * 
 * if you want use the url Base64 alphabet you just prepare opt like this
 * 		<code>
 * 			base64_opt_t opt;
 * 			opt = base64_OPT_EMPTY | base64_OPT_FILENAMESAFE;
 * 		</code>
 *  	
 * <b>Line wrapping</b>
 * the line wrapping make the output in multiline mode. The line size is specified to the 
 * base64_OPT_LINEWRAPPING constant and for a correct preparation of the output space it must
 * be a multiple of 4.
 * 
 * @param in the base64 string
 * @param out pointer to che uchar* variable that will contain the string location of the encoded
 * 			  string. The out is allocated with 'malloc' and it must be deallocate using
 * 			  the 'free' function. The output contain the null terminated symbol (char '\0') for
 * 			  end the string.
 * @param len_in the length of the 'in' input param string
 * @param len_out a pointer to the size_t variable that will contain the the length of the output
 * 			      string. The len_out NOT include the '\0' char (if the output is 'Y2lhbw==' the
 * 				  *len_out is 8 but the allocated memory is 9).
 * @param opt the option (the line wrapping option will be ingored) 
 * 
 * @return if true the encode have success, if false no out was generated and no memory was
 * 		   allocated for the output.
 */
bool base64_encode(ubyte* in, uchar** out, size_t len_in, size_t* len_out, base64_opt_t opt)
{
	uchar *out_pos;
	ubyte alphabet, *in_pos;
	size_t remaining, len_out_l, len_line;
	bool lineWrapping;

	alphabet = (opt & base64_OPT_FILENAMESAFE) ? 1 : 0;
	lineWrapping = (opt & base64_OPT_LINEWRAPPING);
	
	len_out_l = (ceil((float)len_in / 3 ) * 4);
	if(lineWrapping) len_out_l += len_out_l / base64_LINE_LENGTH;
	
	out_pos = *out = (ubyte*)malloc(len_out_l + 1);
	if (*out == NULL) return false;
	
	in_pos = in;
	remaining = len_in;
	len_line = 0;
	
	while (remaining >= 3){
		/* Now we have 3 bytes, it will be divide in 4 group of 6 bits 
		 * and with this 4 group we make 4 bytes filled with the base64_alphabets chars */
		 
		*out_pos = base64_alphabets[alphabet][in_pos[0] >> 2]; out_pos++;
		*out_pos = base64_alphabets[alphabet][((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)]; out_pos++;
		*out_pos = base64_alphabets[alphabet][((in_pos[1] & 0x0F) << 2) | (in_pos[2] >> 6)]; out_pos++;
		*out_pos = base64_alphabets[alphabet][in_pos[2] & 0x3F]; out_pos++;
		
		in_pos += 3;
		remaining -= 3;
		
		if (lineWrapping){ 
			len_line += 4;
			if(len_line == base64_LINE_LENGTH){
				*out_pos = '\n'; out_pos++;
				len_line = 0;
			}
		}
	}
		
	if(remaining > 0){
		/* Now we have 2 or 1 bytes, it will be divide in 3 or 2 group of 6 bits 
		 * and with this 3 or 2 group we make 3 or 2 bytes filled with the base64_alphabets chars 
		 * but we need to add an extra char '=' for every two zero bits used to make the last
		 * group of 6 bits*/
		 
		*out_pos = base64_alphabets[alphabet][in_pos[0] >> 2]; out_pos++;
		
		if(remaining == 2){
			*out_pos = base64_alphabets[alphabet][((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)]; out_pos++;
			*out_pos = base64_alphabets[alphabet][(in_pos[1] & 0x0F) << 2]; out_pos++;
			
			in_pos += 2;
			
		}else{ //remaining == 1
			*out_pos = base64_alphabets[alphabet][(in_pos[0] & 0x03) << 4]; out_pos++;
			*out_pos = '='; out_pos++;
			
			in_pos++;
			
		}
		
		*out_pos = '=';	out_pos++;
		
	}

	*out_pos = '\0';
	*len_out = len_out_l;
	
	return true;
	
}
