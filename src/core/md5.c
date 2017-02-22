/*
 * embedded IPsec	
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file md5.c
 *  @brief RFC 1321 - The MD5 Message-Digest Algorithm and RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *
 *  @author  Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *  This module contains mainly code extracted from the libssl library.
 *  We use this code to implement a HMAC. The functions used to implement the HMAC-MD5
 *  are MD5_Init MD5_Update and MD5_Finish.
 *
 *  <B>IMPLEMENTATION:</B>
 * "This product includes cryptographic software written by
 * Eric Young (eay@cryptsoft.com)" (taken form www.openssl.org)"
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include <string.h>

#include "ipsec/md5.h"
#include "ipsec/debug.h"

unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md)
{
	MD5_CTX c;
	static unsigned char m[MD5_DIGEST_LENGTH];

	if (md == NULL) md=m;
	MD5_Init(&c);
	MD5_Update(&c,d,n);
	MD5_Final(md,&c);
	memset(&c,0,sizeof(c)); /* security consideration */
	return(md);
}


#define INIT_DATA_A (unsigned long)0x67452301L
#define INIT_DATA_B (unsigned long)0xefcdab89L
#define INIT_DATA_C (unsigned long)0x98badcfeL
#define INIT_DATA_D (unsigned long)0x10325476L

void MD5_Init(MD5_CTX *c)
{
	c->A=INIT_DATA_A;
	c->B=INIT_DATA_B;
	c->C=INIT_DATA_C;
	c->D=INIT_DATA_D;
	c->Nl=0;
	c->Nh=0;
	c->num=0;
}


void md5_block_host_order (MD5_CTX *c, const void *p,int num);
void md5_block_data_order (MD5_CTX *c, const void *p,int num);

/*
 * Engage compiler specific rotate intrinsic function if available.
 */

#undef ROTATE

// *** Keil C166 ***
#ifdef __C166__
#include <intrins.h>
#define ROTATE(a,n)	_lrol_(a,n)
#endif


#ifdef ROTATE
/* 5 instructions with rotate instruction, else 9 */
#define REVERSE_FETCH32(a,l)	(					\
		l=*(const MD5_LONG *)(a),				\
		((ROTATE(l,8)&0x00FF00FF)|(ROTATE((l&0x00FF00FF),24)))	\
				)
#endif
                                        

#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))    ),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<<24),		\
			 l)
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
			case 3: l|=((unsigned long)(*((c)++)))<<24;	\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)));		\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<< 8;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<<16;	\
				} }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<<16;	\
			case 2: l|=((unsigned long)(*(--(c))))<< 8;	\
			case 1: l|=((unsigned long)(*(--(c))));		\
				} }
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 l)


/*
 * Time for some action:-)
 */

void MD5_Update (MD5_CTX *c, const void *data_, unsigned long len)
{
	const unsigned char *data=data_;
	MD5_LONG * p;
	unsigned long l;
	int sw,sc,ew,ec;

	if (len==0) return;

	l=(c->Nl+(len<<3))&0xffffffffL;
	/* 95-05-24 eay Fixed a bug with the overflow handling, thanks to
	 * Wei Dai <weidai@eskimo.com> for pointing it out. */
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh+=(len>>29);
	c->Nl=l;

	if (c->num != 0)
		{
		p=c->data;
		sw=c->num>>2;
		sc=c->num&0x03;

		if ((c->num+len) >= MD5_CBLOCK)
			{
			l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
			for (; sw<MD5_LBLOCK; sw++)
				{
				HOST_c2l(data,l); p[sw]=l;
				}
			md5_block_host_order (c,p,1);
			len-=(MD5_CBLOCK-c->num);
			c->num=0;
			/* drop through and do the rest */
			}
		else
			{
			c->num+=len;
			if ((sc+len) < 4) /* ugly, add char's to a word */
				{
				l=p[sw]; HOST_p_c2l_p(data,l,sc,len); p[sw]=l;
				}
			else
				{
				ew=(c->num>>2);
				ec=(c->num&0x03);
				l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
				for (; sw < ew; sw++)
					{
					HOST_c2l(data,l); p[sw]=l;
					}
				if (ec)
					{
					HOST_c2l_p(data,l,ec); p[sw]=l;
					}
				}
			return;
			}
		}

	sw=(int) (len/MD5_CBLOCK);
	if (sw > 0)
		{
		if ((((unsigned long)data)%4) == 0)
			{
			/* data is properly aligned so that we can cast it: */
			md5_block_host_order (c,(MD5_LONG *)data,sw);
			sw*=MD5_CBLOCK;
			data+=sw;
			len-=sw;
			}
		else
			{
			md5_block_data_order(c,data,sw);
			sw*=MD5_CBLOCK;
			data+=sw;
			len-=sw;
			}
		}

	if (len!=0)
		{
		p = c->data;
		c->num = (int) len;
		ew=(int) (len>>2);	/* words to copy */
		ec=(int) (len&0x03);
		for (; ew; ew--,p++)
			{
			HOST_c2l(data,l); *p=l;
			}
		HOST_c2l_p(data,l,ec);
		*p=l;
		}
}


void MD5_Transform (MD5_CTX *c, const unsigned char *data)
{
	if ((((unsigned long)data)%4) == 0)
		/* data is properly aligned so that we can cast it: */
		md5_block_host_order (c,(MD5_LONG *)data,1);
	else
	md5_block_data_order (c,data,1);
}


void MD5_Final (unsigned char *md, MD5_CTX *c)
{
	MD5_LONG *p;
	unsigned long l;
	int i,j;
	static const unsigned char end[4]={0x80,0x00,0x00,0x00};
	const unsigned char *cp=end;

	/* c->num should definitly have room for at least one more byte. */
	p=c->data;
	i=c->num>>2;
	j=c->num&0x03;

	l = (j==0) ? 0 : p[i];

	HOST_p_c2l(cp,l,j); p[i++]=l; /* i is the next 'undefined word' */

	if (i>(MD5_LBLOCK-2)) /* save room for Nl and Nh */
		{
		if (i<MD5_LBLOCK) p[i]=0;
		md5_block_host_order (c,p,1);
		i=0;
		}
	for (; i<(MD5_LBLOCK-2); i++)
		p[i]=0;

	p[MD5_LBLOCK-2]=c->Nl;
	p[MD5_LBLOCK-1]=c->Nh;
	md5_block_host_order (c,p,1);


	// HASH_MAKE_STRING(c,md);
	do {	
	unsigned long ll;		
	ll=(c)->A; HOST_l2c(ll,(md));	
	ll=(c)->B; HOST_l2c(ll,(md));	
	ll=(c)->C; HOST_l2c(ll,(md));	
	ll=(c)->D; HOST_l2c(ll,(md));	
	} while (0);


	c->num=0;
	/* clear stuff, HASH_BLOCK may be leaving some stuff on the stack
	 * but I'm not worried :-)
	memset((void *)c,0,sizeof(MD5_CTX));
	 */
}


#define	F(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	G(b,c,d)	((((b) ^ (c)) & (d)) ^ (c))
#define	H(b,c,d)	((b) ^ (c) ^ (d))
#define	I(b,c,d)	(((~(d)) | (b)) ^ (c))

#define R0(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+F((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };\

#define R1(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+G((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R2(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+H((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };

#define R3(a,b,c,d,k,s,t) { \
	a+=((k)+(t)+I((b),(c),(d))); \
	a=ROTATE(a,s); \
	a+=b; };



void md5_block_host_order (MD5_CTX *c, const void *data, int num)
{
	const MD5_LONG *X=data;
	unsigned long A,B,C,D;
	/*
	 * In case you wonder why A-D are declared as long and not
	 * as MD5_LONG. Doing so results in slight performance
	 * boost on LP64 architectures. The catch is we don't
	 * really care if 32 MSBs of a 64-bit register get polluted
	 * with eventual overflows as we *save* only 32 LSBs in
	 * *either* case. Now declaring 'em long excuses the compiler
	 * from keeping 32 MSBs zeroed resulting in 13% performance
	 * improvement under SPARC Solaris7/64 and 5% under AlphaLinux.
	 * Well, to be honest it should say that this *prevents* 
	 * performance degradation.
	 *
	 *				<appro@fy.chalmers.se>
	 */

	A=c->A;
	B=c->B;
	C=c->C;
	D=c->D;

	for (;num--;X+=MD5_LBLOCK)
		{
	/* Round 0 */
	R0(A,B,C,D,X[ 0], 7,0xd76aa478L);
	R0(D,A,B,C,X[ 1],12,0xe8c7b756L);
	R0(C,D,A,B,X[ 2],17,0x242070dbL);
	R0(B,C,D,A,X[ 3],22,0xc1bdceeeL);
	R0(A,B,C,D,X[ 4], 7,0xf57c0fafL);
	R0(D,A,B,C,X[ 5],12,0x4787c62aL);
	R0(C,D,A,B,X[ 6],17,0xa8304613L);
	R0(B,C,D,A,X[ 7],22,0xfd469501L);
	R0(A,B,C,D,X[ 8], 7,0x698098d8L);
	R0(D,A,B,C,X[ 9],12,0x8b44f7afL);
	R0(C,D,A,B,X[10],17,0xffff5bb1L);
	R0(B,C,D,A,X[11],22,0x895cd7beL);
	R0(A,B,C,D,X[12], 7,0x6b901122L);
	R0(D,A,B,C,X[13],12,0xfd987193L);
	R0(C,D,A,B,X[14],17,0xa679438eL);
	R0(B,C,D,A,X[15],22,0x49b40821L);
	/* Round 1 */
	R1(A,B,C,D,X[ 1], 5,0xf61e2562L);
	R1(D,A,B,C,X[ 6], 9,0xc040b340L);
	R1(C,D,A,B,X[11],14,0x265e5a51L);
	R1(B,C,D,A,X[ 0],20,0xe9b6c7aaL);
	R1(A,B,C,D,X[ 5], 5,0xd62f105dL);
	R1(D,A,B,C,X[10], 9,0x02441453L);
	R1(C,D,A,B,X[15],14,0xd8a1e681L);
	R1(B,C,D,A,X[ 4],20,0xe7d3fbc8L);
	R1(A,B,C,D,X[ 9], 5,0x21e1cde6L);
	R1(D,A,B,C,X[14], 9,0xc33707d6L);
	R1(C,D,A,B,X[ 3],14,0xf4d50d87L);
	R1(B,C,D,A,X[ 8],20,0x455a14edL);
	R1(A,B,C,D,X[13], 5,0xa9e3e905L);
	R1(D,A,B,C,X[ 2], 9,0xfcefa3f8L);
	R1(C,D,A,B,X[ 7],14,0x676f02d9L);
	R1(B,C,D,A,X[12],20,0x8d2a4c8aL);
	/* Round 2 */
	R2(A,B,C,D,X[ 5], 4,0xfffa3942L);
	R2(D,A,B,C,X[ 8],11,0x8771f681L);
	R2(C,D,A,B,X[11],16,0x6d9d6122L);
	R2(B,C,D,A,X[14],23,0xfde5380cL);
	R2(A,B,C,D,X[ 1], 4,0xa4beea44L);
	R2(D,A,B,C,X[ 4],11,0x4bdecfa9L);
	R2(C,D,A,B,X[ 7],16,0xf6bb4b60L);
	R2(B,C,D,A,X[10],23,0xbebfbc70L);
	R2(A,B,C,D,X[13], 4,0x289b7ec6L);
	R2(D,A,B,C,X[ 0],11,0xeaa127faL);
	R2(C,D,A,B,X[ 3],16,0xd4ef3085L);
	R2(B,C,D,A,X[ 6],23,0x04881d05L);
	R2(A,B,C,D,X[ 9], 4,0xd9d4d039L);
	R2(D,A,B,C,X[12],11,0xe6db99e5L);
	R2(C,D,A,B,X[15],16,0x1fa27cf8L);
	R2(B,C,D,A,X[ 2],23,0xc4ac5665L);
	/* Round 3 */
	R3(A,B,C,D,X[ 0], 6,0xf4292244L);
	R3(D,A,B,C,X[ 7],10,0x432aff97L);
	R3(C,D,A,B,X[14],15,0xab9423a7L);
	R3(B,C,D,A,X[ 5],21,0xfc93a039L);
	R3(A,B,C,D,X[12], 6,0x655b59c3L);
	R3(D,A,B,C,X[ 3],10,0x8f0ccc92L);
	R3(C,D,A,B,X[10],15,0xffeff47dL);
	R3(B,C,D,A,X[ 1],21,0x85845dd1L);
	R3(A,B,C,D,X[ 8], 6,0x6fa87e4fL);
	R3(D,A,B,C,X[15],10,0xfe2ce6e0L);
	R3(C,D,A,B,X[ 6],15,0xa3014314L);
	R3(B,C,D,A,X[13],21,0x4e0811a1L);
	R3(A,B,C,D,X[ 4], 6,0xf7537e82L);
	R3(D,A,B,C,X[11],10,0xbd3af235L);
	R3(C,D,A,B,X[ 2],15,0x2ad7d2bbL);
	R3(B,C,D,A,X[ 9],21,0xeb86d391L);

	A = c->A += A;
	B = c->B += B;
	C = c->C += C;
	D = c->D += D;
		}
}


void md5_block_data_order (MD5_CTX *c, const void *data_, int num)
{
	const unsigned char *data=data_;
	unsigned long A,B,C,D,l;
	/*
	 * In case you wonder why A-D are declared as long and not
	 * as MD5_LONG. Doing so results in slight performance
	 * boost on LP64 architectures. The catch is we don't
	 * really care if 32 MSBs of a 64-bit register get polluted
	 * with eventual overflows as we *save* only 32 LSBs in
	 * *either* case. Now declaring 'em long excuses the compiler
	 * from keeping 32 MSBs zeroed resulting in 13% performance
	 * improvement under SPARC Solaris7/64 and 5% under AlphaLinux.
	 * Well, to be honest it should say that this *prevents* 
	 * performance degradation.
	 *
	 *				<appro@fy.chalmers.se>
	 */
	unsigned long	XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
			XX8, XX9,XX10,XX11,XX12,XX13,XX14,XX15;
#define X(i)	XX##i

	A=c->A;
	B=c->B;
	C=c->C;
	D=c->D;

	for (;num--;)
		{
	HOST_c2l(data,l); X( 0)=l;		HOST_c2l(data,l); X( 1)=l;
	/* Round 0 */
	R0(A,B,C,D,X( 0), 7,0xd76aa478L);	HOST_c2l(data,l); X( 2)=l;
	R0(D,A,B,C,X( 1),12,0xe8c7b756L);	HOST_c2l(data,l); X( 3)=l;
	R0(C,D,A,B,X( 2),17,0x242070dbL);	HOST_c2l(data,l); X( 4)=l;
	R0(B,C,D,A,X( 3),22,0xc1bdceeeL);	HOST_c2l(data,l); X( 5)=l;
	R0(A,B,C,D,X( 4), 7,0xf57c0fafL);	HOST_c2l(data,l); X( 6)=l;
	R0(D,A,B,C,X( 5),12,0x4787c62aL);	HOST_c2l(data,l); X( 7)=l;
	R0(C,D,A,B,X( 6),17,0xa8304613L);	HOST_c2l(data,l); X( 8)=l;
	R0(B,C,D,A,X( 7),22,0xfd469501L);	HOST_c2l(data,l); X( 9)=l;
	R0(A,B,C,D,X( 8), 7,0x698098d8L);	HOST_c2l(data,l); X(10)=l;
	R0(D,A,B,C,X( 9),12,0x8b44f7afL);	HOST_c2l(data,l); X(11)=l;
	R0(C,D,A,B,X(10),17,0xffff5bb1L);	HOST_c2l(data,l); X(12)=l;
	R0(B,C,D,A,X(11),22,0x895cd7beL);	HOST_c2l(data,l); X(13)=l;
	R0(A,B,C,D,X(12), 7,0x6b901122L);	HOST_c2l(data,l); X(14)=l;
	R0(D,A,B,C,X(13),12,0xfd987193L);	HOST_c2l(data,l); X(15)=l;
	R0(C,D,A,B,X(14),17,0xa679438eL);
	R0(B,C,D,A,X(15),22,0x49b40821L);
	/* Round 1 */
	R1(A,B,C,D,X( 1), 5,0xf61e2562L);
	R1(D,A,B,C,X( 6), 9,0xc040b340L);
	R1(C,D,A,B,X(11),14,0x265e5a51L);
	R1(B,C,D,A,X( 0),20,0xe9b6c7aaL);
	R1(A,B,C,D,X( 5), 5,0xd62f105dL);
	R1(D,A,B,C,X(10), 9,0x02441453L);
	R1(C,D,A,B,X(15),14,0xd8a1e681L);
	R1(B,C,D,A,X( 4),20,0xe7d3fbc8L);
	R1(A,B,C,D,X( 9), 5,0x21e1cde6L);
	R1(D,A,B,C,X(14), 9,0xc33707d6L);
	R1(C,D,A,B,X( 3),14,0xf4d50d87L);
	R1(B,C,D,A,X( 8),20,0x455a14edL);
	R1(A,B,C,D,X(13), 5,0xa9e3e905L);
	R1(D,A,B,C,X( 2), 9,0xfcefa3f8L);
	R1(C,D,A,B,X( 7),14,0x676f02d9L);
	R1(B,C,D,A,X(12),20,0x8d2a4c8aL);
	/* Round 2 */
	R2(A,B,C,D,X( 5), 4,0xfffa3942L);
	R2(D,A,B,C,X( 8),11,0x8771f681L);
	R2(C,D,A,B,X(11),16,0x6d9d6122L);
	R2(B,C,D,A,X(14),23,0xfde5380cL);
	R2(A,B,C,D,X( 1), 4,0xa4beea44L);
	R2(D,A,B,C,X( 4),11,0x4bdecfa9L);
	R2(C,D,A,B,X( 7),16,0xf6bb4b60L);
	R2(B,C,D,A,X(10),23,0xbebfbc70L);
	R2(A,B,C,D,X(13), 4,0x289b7ec6L);
	R2(D,A,B,C,X( 0),11,0xeaa127faL);
	R2(C,D,A,B,X( 3),16,0xd4ef3085L);
	R2(B,C,D,A,X( 6),23,0x04881d05L);
	R2(A,B,C,D,X( 9), 4,0xd9d4d039L);
	R2(D,A,B,C,X(12),11,0xe6db99e5L);
	R2(C,D,A,B,X(15),16,0x1fa27cf8L);
	R2(B,C,D,A,X( 2),23,0xc4ac5665L);
	/* Round 3 */
	R3(A,B,C,D,X( 0), 6,0xf4292244L);
	R3(D,A,B,C,X( 7),10,0x432aff97L);
	R3(C,D,A,B,X(14),15,0xab9423a7L);
	R3(B,C,D,A,X( 5),21,0xfc93a039L);
	R3(A,B,C,D,X(12), 6,0x655b59c3L);
	R3(D,A,B,C,X( 3),10,0x8f0ccc92L);
	R3(C,D,A,B,X(10),15,0xffeff47dL);
	R3(B,C,D,A,X( 1),21,0x85845dd1L);
	R3(A,B,C,D,X( 8), 6,0x6fa87e4fL);
	R3(D,A,B,C,X(15),10,0xfe2ce6e0L);
	R3(C,D,A,B,X( 6),15,0xa3014314L);
	R3(B,C,D,A,X(13),21,0x4e0811a1L);
	R3(A,B,C,D,X( 4), 6,0xf7537e82L);
	R3(D,A,B,C,X(11),10,0xbd3af235L);
	R3(C,D,A,B,X( 2),15,0x2ad7d2bbL);
	R3(B,C,D,A,X( 9),21,0xeb86d391L);

	A = c->A += A;
	B = c->B += B;
	C = c->C += C;
	D = c->D += D;
		}
}



 /**
 * RFC 2104 hmac_md5 function calculates a digest from a given data buffer and a given key.
 *
 * @param text		pointer to data stream
 * @param text_len	length of data stream
 * @param key		pointer to authentication key
 * @param key_len	length of authentication key
 * @param digest	caller digest to be filled in 128-bit
 * @return void
 *
 */
void hmac_md5(unsigned char* text, int text_len, unsigned char*  key, int key_len, unsigned char*  digest)
{
    MD5_CTX context;
    unsigned char k_ipad[65];    /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];    /* outer padding - key XORd with opad */
    unsigned char tk[16];	 	 /* L=16 for MD5 (RFC 2141, 2. Definition of HMAC) */
    int i;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "hmac_md5", 
				  ("text=%p, text_len=%d, key=%p, key_len=%d, digest=%p",
			      (void *)text, text_len, (void *)key, key_len, (void *)digest)
				 );


    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if (key_len > 64) {

            MD5_CTX      tctx;

            MD5_Init(&tctx);
            MD5_Update(&tctx, key, key_len);
            MD5_Final(tk, &tctx);

            key = tk;
            key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */
    memset(k_ipad, '\0', sizeof(k_ipad));
    memset(k_opad, '\0', sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);


    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    MD5_Init(&context);                  /* init context for 1st
                                          * pass */
    MD5_Update(&context, k_ipad, 64);    /* start with inner pad */
    MD5_Update(&context, text, text_len);/* then text of datagram */
    MD5_Final(digest, &context);         /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    MD5_Init(&context);                  /* init context for 2nd
                                          * pass */
    MD5_Update(&context, k_opad, 64);    /* start with outer pad */
    MD5_Update(&context, digest, 16);    /* then results of 1st
                                          * hash */
    MD5_Final(digest, &context);         /* finish up 2nd pass */

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "hmac_md5", ("void") );
}

