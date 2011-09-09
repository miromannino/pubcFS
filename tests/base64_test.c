/*
 * Copyright 2010 Miro Mannino <miro.mannino@gmail.com>
 * This work is licensed under the Creative Commons Attribution 2.5
 * Italy License. To view a copy of this license, visit
 * http://creativecommons.org/licenses/by/2.5/it/ or send a letter
 * to Creative Commons, 171 Second Street, Suite 300, San Francisco,
 * California, 94105, USA.
 * 
 */ 

#include <base64.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* this code will be used for test the base64 algorithms */
/* for use this test 
	gcc -I. -lm base64_test.c base64.c
	./a.out
*/

int main(){
	int i,j,y;
	uchar *a, *b, *c;
	size_t len1, len2;
	base64_opt_t opt;
	
	srand(time(NULL));
	a = malloc(1000);
	
	for(j=170; j<1000; j++){
		printf("string size = %d\n", j);
		for(i=0; i<1000; i++){
			opt = base64_OPT_EMPTY;
			if(i%1 == 0) opt = opt | base64_OPT_FILENAMESAFE;
			if(i%2 == 0) opt = opt | base64_OPT_LINEWRAPPING;
			
			//for(y=0; y<j; y++) a[y] = (uchar)(rand() % 24) + 'a';
			for(y=0; y<j; y++) a[y] = (uchar)(rand() % 255) + 'a';
			/*printf("insert: ");
			scanf("%s", a);
			j = strlen(a);*/
			
			//printf("original = %s\n", a);
			if (base64_encode(a, &b, j, &len1, opt) != true){
				printf("encode fail\n");
				continue;
			}
			
			/*printf("insert encoded: ");
			b = malloc(255);
			scanf("%s", b);
			len1 = strlen(b);*/
			
			//printf("encoded = %s\n", b);
			if (base64_decode(b, &c, len1, &len2, opt) != true){
				printf("decode fail\n");
				free(b);
				continue;
			}
			
			//printf("decoded = %s\n", c);
			if(len2 != j){
				printf("Error: len2 != j\n");
				
				for(y=0; y<j; y++) printf("%d ", a[y]);
				printf("\n\n");
				for(y=0; y<len2; y++) printf("%d ", c[y]);
				printf("\n\n");
				
				printf("  len2 = %u\n", (uint)len2);
				
				printf("  j = %d\n", j);
				printf("  a = %s\n", a);
				printf("  b = %s\n", b);
				printf("  c = %s\n", c);
				
			}else if(memcmp(a,c,j) != 0){
				printf("Error: memcmp(a,c,j) != 0\n");
				
				for(y=0; y<j; y++) printf("%d ", a[y]);
				printf("\n\n");
				for(y=0; y<j; y++) printf("%d ", c[y]);
				printf("\n\n");
				
				printf("  j = %d\n", j);
				printf("  a = %s\n", a);
				printf("  b = %s\n", b);
				printf("  c = %s\n", c);
			}
			
			free(c);
			free(b);
			
		}
	}
	return 0;
}
