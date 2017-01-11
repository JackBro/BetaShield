#pragma once
#include <string>

const unsigned char B64_offset[256] =
{
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};
const char base64_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

class CBase64
{
public:
	CBase64(){}

	char *Encrypt(const char * srcp, int len, char * dstp)
	{
		register int i = 0;
		char *dst = dstp;

		for (i = 0; i < len - 2; i += 3)
		{
			*dstp++ = *(base64_map + ((*(srcp+i)>>2)&0x3f));
			*dstp++ = *(base64_map + ((*(srcp+i)<< 4)&0x30 | (*(srcp+i+1)>>4)&0x0f ));
			*dstp++ = *(base64_map + ((*(srcp+i+1)<<2)&0x3C | (*(srcp+i+2)>>6)&0x03));
			*dstp++ = *(base64_map + (*(srcp+i+2)&0x3f));
		}
		srcp += i;
		len -= i;

		if(len & 0x02 ) /* (i==2) 2 bytes left,pad one byte of '=' */
		{      
			*dstp++ = *(base64_map + ((*srcp>>2)&0x3f));
			*dstp++ = *(base64_map + ((*srcp<< 4)&0x30 | (*(srcp+1)>>4)&0x0f ));
			*dstp++ = *(base64_map + ((*(srcp+1)<<2)&0x3C) );
			*dstp++ = '=';
		}
		else if(len & 0x01 )  /* (i==1) 1 byte left,pad two bytes of '='  */
		{ 
			*dstp++ = *(base64_map + ((*srcp>>2)&0x3f));
			*dstp++ = *(base64_map + ((*srcp<< 4)&0x30));
			*dstp++ = '=';
			*dstp++ = '=';
		}

		*dstp = '\0';

		return dst;
	}

	void *Decrypt(const char * srcp, int len, char * dstp)
	{
		register int i = 0;
		void *dst = dstp;

		while(i < len)
		{
			*dstp++ = (B64_offset[*(srcp+i)] <<2 | B64_offset[*(srcp+i+1)] >>4);
			*dstp++ = (B64_offset[*(srcp+i+1)]<<4 | B64_offset[*(srcp+i+2)]>>2);
			*dstp++ = (B64_offset[*(srcp+i+2)]<<6 | B64_offset[*(srcp+i+3)] );
			i += 4;
		}
		srcp += i;
		
		if(*(srcp-2) == '=')  /* remove 2 bytes of '='  padded while encoding */
		{	 
			*(dstp--) = '\0';
			*(dstp--) = '\0';
		}
		else if(*(srcp-1) == '=') /* remove 1 byte of '='  padded while encoding */
			*(dstp--) = '\0';

		*dstp = '\0';

		return dst;
	};

	size_t B64_length(size_t len)
	{
		size_t  npad = len%3;
		size_t  size = (npad > 0)? (len +3-npad ) : len; // padded for multiple of 3 bytes
		return  (size*8)/6;
	}

	size_t Ascii_length(size_t len)
	{
		return  (len*6)/8;
	}
};
