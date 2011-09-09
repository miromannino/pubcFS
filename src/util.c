#include <util.h>

size_t writen(int fd, ubyte* buf, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	byte* ptr;

	ptr = (void*)buf;
	nleft = n;

	while(nleft > 0){
		if((nwritten = write(fd, ptr, nleft)) < 0){
			if(errno == EINTR) nwritten = 0; /* and call write() again*/
			else return(-1); /* error */
		}
		nleft -= nwritten;
		ptr += nwritten;
	}

	return(n);
}

size_t readn(int fd, ubyte* ptr, size_t nbytes)
{
	int nleft, nread;

	nleft = nbytes;

	while(nleft > 0){
		do{
			nread = read(fd, ptr, nleft);
		}while((nread < 0) && (errno == EINTR));

		if(nread < 0){ /* error */
			return(-1);
		}else{
			if(nread == 0){
				return(0);
				break;
			}
		}

		nleft -= nread;
		ptr += nread;
	}

	return(nbytes);
}

//this only work with dinamic allocated strings
char* strappend(char* a, char* b)
{
	int a_size, b_size;
	char* ris;

	a_size = strlen(a);
	b_size = strlen(b);
	ris = realloc(a, a_size + b_size + 1);
	if (ris == NULL) return NULL;
	strcat(ris, b);

	return ris;
}
