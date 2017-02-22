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

/** @file sha1.c
 *  @brief RFC 3174 - US Secure Hash Algorithm 1 (SHA1) and RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *
 *  @author  Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *   RFC3174 (US Secure Hash Algorithm 1 (SHA1)) implementation.
 *   Requires Infineon C167 MCU and Keil C166 compiler.
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
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)</EM><HR>
 */

#include <string.h>

#include "ipsec/sha1.h"
#include "ipsec/debug.h"


unsigned char *SHA1(const unsigned char *d, unsigned long n, unsigned char *md)
{
	SHA_CTX c;
	static unsigned char m[SHA_DIGEST_LENGTH];

	if (md == NULL) md=m;
	SHA1_Init(&c);
	SHA1_Update(&c,d,n);
	SHA1_Final(md,&c);
	memset(&c,0,sizeof(c));
	return(md);
}


#define Xupdate(a,ix,ia,ib,ic,id)	( (a)=(ia^ib^ic^id),	\
					  ix=(a)=ROTATE((a),1)	\
					)

void sha1_block_host_order (SHA_CTX *c, const void *p,int num);
void sha1_block_data_order (SHA_CTX *c, const void *p,int num);



#define SHA_CBLOCK	(SHA_LBLOCK*4)	/* SHA treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)




#ifndef SHA_LBLOCK
#define SHA_LBLOCK	(SHA_CBLOCK/4)
#endif


/*
 * Engage compiler specific rotate intrinsic function if available.
 */

#undef ROTATE

// *** Keil C166 ***
#ifdef __C166__
#include <intrins.h>
#define ROTATE(a,n)	_lrol_(a,n)
#endif


/* A nice byte order reversal from Wei Dai <weidai@eskimo.com> */
#ifdef ROTATE
/* 5 instructions with rotate instruction, else 9 */
#define REVERSE_FETCH32(a,l)	(					\
		l=*(const SHA_LONG *)(a),				\
		((ROTATE(l,8)&0x00FF00FF)|(ROTATE((l&0x00FF00FF),24)))	\
				)
#endif


// #if defined(DATA_ORDER_IS_BIG_ENDIAN)
#define HOST_c2l(c,l)	(l =(((unsigned long)(*((c)++)))<<24),		\
			 l|=(((unsigned long)(*((c)++)))<<16),		\
			 l|=(((unsigned long)(*((c)++)))<< 8),		\
			 l|=(((unsigned long)(*((c)++)))    ),		\
			 l)
#define HOST_p_c2l(c,l,n)	{					\
			switch (n) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
			case 3: l|=((unsigned long)(*((c)++)));		\
				} }
#define HOST_p_c2l_p(c,l,sc,len) {					\
			switch (sc) {					\
			case 0: l =((unsigned long)(*((c)++)))<<24;	\
				if (--len == 0) break;			\
			case 1: l|=((unsigned long)(*((c)++)))<<16;	\
				if (--len == 0) break;			\
			case 2: l|=((unsigned long)(*((c)++)))<< 8;	\
				} }
// NOTE the pointer is not incremented at the end of this
#define HOST_c2l_p(c,l,n)	{					\
			l=0; (c)+=n;					\
			switch (n) {					\
			case 3: l =((unsigned long)(*(--(c))))<< 8;	\
			case 2: l|=((unsigned long)(*(--(c))))<<16;	\
			case 1: l|=((unsigned long)(*(--(c))))<<24;	\
				} }
#define HOST_l2c(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff),	\
			 l)


/*
 * Time for some action:-)
 */

void SHA1_Update (SHA_CTX *c, const void *data_, unsigned long len)
{
	const unsigned char *data=data_;
	SHA_LONG * p;
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

		if ((c->num+len) >= SHA_CBLOCK)
			{
			l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
			for (; sw<SHA_LBLOCK; sw++)
				{
				HOST_c2l(data,l); p[sw]=l;
				}
			sha1_block_host_order (c,p,1);
			len-=(SHA_CBLOCK-c->num);
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

	sw=(int)(len/SHA_CBLOCK);
	if (sw > 0)
		{
			{
			sha1_block_data_order(c,data,sw);
			sw*=SHA_CBLOCK;
			data+=sw;
			len-=sw;
			}
		}

	if (len!=0)
		{
		p = c->data;
		c->num = (int)len;
		ew=(int)(len>>2);	/* words to copy */
		ec=(int)(len&0x03);
		for (; ew; ew--,p++)
			{
			HOST_c2l(data,l); *p=l;
			}
		HOST_c2l_p(data,l,ec);
		*p=l;
		}
}


void SHA1_Transform (SHA_CTX *c, const unsigned char *data)
{
	sha1_block_data_order (c,data,1);
}


void SHA1_Final (unsigned char *md, SHA_CTX *c)
{
	SHA_LONG *p;
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

	if (i>(SHA_LBLOCK-2)) /* save room for Nl and Nh */
		{
		if (i<SHA_LBLOCK) p[i]=0;
		sha1_block_host_order (c,p,1);
		i=0;
		}
	for (; i<(SHA_LBLOCK-2); i++)
		p[i]=0;

	p[SHA_LBLOCK-2]=c->Nh;
	p[SHA_LBLOCK-1]=c->Nl;

	sha1_block_host_order (c,p,1);

	// HASH_MAKE_STRING(c,md);
	do {
	unsigned long ll;
	ll=(c)->h0; HOST_l2c(ll,(md));
	ll=(c)->h1; HOST_l2c(ll,(md));
	ll=(c)->h2; HOST_l2c(ll,(md));
	ll=(c)->h3; HOST_l2c(ll,(md));
	ll=(c)->h4; HOST_l2c(ll,(md));
	} while (0);

	c->num=0;
	/* clear stuff, HASH_BLOCK may be leaving some stuff on the stack
	 * but I'm not worried :-)
	memset((void *)c,0,sizeof(SHA_CTX));
	 */
}



#define INIT_DATA_h0 0x67452301UL
#define INIT_DATA_h1 0xefcdab89UL
#define INIT_DATA_h2 0x98badcfeUL
#define INIT_DATA_h3 0x10325476UL
#define INIT_DATA_h4 0xc3d2e1f0UL

void SHA1_Init (SHA_CTX *c)
{
	c->h0=INIT_DATA_h0;
	c->h1=INIT_DATA_h1;
	c->h2=INIT_DATA_h2;
	c->h3=INIT_DATA_h3;
	c->h4=INIT_DATA_h4;
	c->Nl=0;
	c->Nh=0;
	c->num=0;
}

#define K_00_19	0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

/* As  pointed out by Wei Dai <weidai@eskimo.com>, F() below can be
 * simplified to the code in F_00_19.  Wei attributes these optimisations
 * to Peter Gutmann's SHS code, and he attributes it to Rich Schroeppel.
 * #define F(x,y,z) (((x) & (y))  |  ((~(x)) & (z)))
 * I've just become aware of another tweak to be made, again from Wei Dai,
 * in F_40_59, (x&a)|(y&a) -> (x|y)&a
 */
#define	F_00_19(b,c,d)	((((c) ^ (d)) & (b)) ^ (d))
#define	F_20_39(b,c,d)	((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)	(((b) & (c)) | (((b)|(c)) & (d)))
#define	F_60_79(b,c,d)	F_20_39(b,c,d)

#define BODY_00_15(i,a,b,c,d,e,f,xi) \
	(f)=xi+(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_16_19(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
	Xupdate(f,xi,xa,xb,xc,xd); \
	(f)+=(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_20_31(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
	Xupdate(f,xi,xa,xb,xc,xd); \
	(f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_32_39(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_40_59(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)+=(e)+K_40_59+ROTATE((a),5)+F_40_59((b),(c),(d)); \
	(b)=ROTATE((b),30);

#define BODY_60_79(i,a,b,c,d,e,f,xa,xb,xc,xd) \
	Xupdate(f,xa,xa,xb,xc,xd); \
	(f)=xa+(e)+K_60_79+ROTATE((a),5)+F_60_79((b),(c),(d)); \
	(b)=ROTATE((b),30);


#define X(i)	XX##i

void sha1_block_host_order (SHA_CTX *c, const void *d, int num)
{
	const SHA_LONG *W=d;
	unsigned long A,B,C,D,E,T;
	unsigned long	XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
			XX8, XX9,XX10,XX11,XX12,XX13,XX14,XX15;

	A=c->h0;
	B=c->h1;
	C=c->h2;
	D=c->h3;
	E=c->h4;

	for (;;)
		{
	BODY_00_15( 0,A,B,C,D,E,T,W[ 0]);
	BODY_00_15( 1,T,A,B,C,D,E,W[ 1]);
	BODY_00_15( 2,E,T,A,B,C,D,W[ 2]);
	BODY_00_15( 3,D,E,T,A,B,C,W[ 3]);
	BODY_00_15( 4,C,D,E,T,A,B,W[ 4]);
	BODY_00_15( 5,B,C,D,E,T,A,W[ 5]);
	BODY_00_15( 6,A,B,C,D,E,T,W[ 6]);
	BODY_00_15( 7,T,A,B,C,D,E,W[ 7]);
	BODY_00_15( 8,E,T,A,B,C,D,W[ 8]);
	BODY_00_15( 9,D,E,T,A,B,C,W[ 9]);
	BODY_00_15(10,C,D,E,T,A,B,W[10]);
	BODY_00_15(11,B,C,D,E,T,A,W[11]);
	BODY_00_15(12,A,B,C,D,E,T,W[12]);
	BODY_00_15(13,T,A,B,C,D,E,W[13]);
	BODY_00_15(14,E,T,A,B,C,D,W[14]);
	BODY_00_15(15,D,E,T,A,B,C,W[15]);

	BODY_16_19(16,C,D,E,T,A,B,X( 0),W[ 0],W[ 2],W[ 8],W[13]);
	BODY_16_19(17,B,C,D,E,T,A,X( 1),W[ 1],W[ 3],W[ 9],W[14]);
	BODY_16_19(18,A,B,C,D,E,T,X( 2),W[ 2],W[ 4],W[10],W[15]);
	BODY_16_19(19,T,A,B,C,D,E,X( 3),W[ 3],W[ 5],W[11],X( 0));

	BODY_20_31(20,E,T,A,B,C,D,X( 4),W[ 4],W[ 6],W[12],X( 1));
	BODY_20_31(21,D,E,T,A,B,C,X( 5),W[ 5],W[ 7],W[13],X( 2));
	BODY_20_31(22,C,D,E,T,A,B,X( 6),W[ 6],W[ 8],W[14],X( 3));
	BODY_20_31(23,B,C,D,E,T,A,X( 7),W[ 7],W[ 9],W[15],X( 4));
	BODY_20_31(24,A,B,C,D,E,T,X( 8),W[ 8],W[10],X( 0),X( 5));
	BODY_20_31(25,T,A,B,C,D,E,X( 9),W[ 9],W[11],X( 1),X( 6));
	BODY_20_31(26,E,T,A,B,C,D,X(10),W[10],W[12],X( 2),X( 7));
	BODY_20_31(27,D,E,T,A,B,C,X(11),W[11],W[13],X( 3),X( 8));
	BODY_20_31(28,C,D,E,T,A,B,X(12),W[12],W[14],X( 4),X( 9));
	BODY_20_31(29,B,C,D,E,T,A,X(13),W[13],W[15],X( 5),X(10));
	BODY_20_31(30,A,B,C,D,E,T,X(14),W[14],X( 0),X( 6),X(11));
	BODY_20_31(31,T,A,B,C,D,E,X(15),W[15],X( 1),X( 7),X(12));

	BODY_32_39(32,E,T,A,B,C,D,X( 0),X( 2),X( 8),X(13));
	BODY_32_39(33,D,E,T,A,B,C,X( 1),X( 3),X( 9),X(14));
	BODY_32_39(34,C,D,E,T,A,B,X( 2),X( 4),X(10),X(15));
	BODY_32_39(35,B,C,D,E,T,A,X( 3),X( 5),X(11),X( 0));
	BODY_32_39(36,A,B,C,D,E,T,X( 4),X( 6),X(12),X( 1));
	BODY_32_39(37,T,A,B,C,D,E,X( 5),X( 7),X(13),X( 2));
	BODY_32_39(38,E,T,A,B,C,D,X( 6),X( 8),X(14),X( 3));
	BODY_32_39(39,D,E,T,A,B,C,X( 7),X( 9),X(15),X( 4));

	BODY_40_59(40,C,D,E,T,A,B,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(41,B,C,D,E,T,A,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(42,A,B,C,D,E,T,X(10),X(12),X( 2),X( 7));
	BODY_40_59(43,T,A,B,C,D,E,X(11),X(13),X( 3),X( 8));
	BODY_40_59(44,E,T,A,B,C,D,X(12),X(14),X( 4),X( 9));
	BODY_40_59(45,D,E,T,A,B,C,X(13),X(15),X( 5),X(10));
	BODY_40_59(46,C,D,E,T,A,B,X(14),X( 0),X( 6),X(11));
	BODY_40_59(47,B,C,D,E,T,A,X(15),X( 1),X( 7),X(12));
	BODY_40_59(48,A,B,C,D,E,T,X( 0),X( 2),X( 8),X(13));
	BODY_40_59(49,T,A,B,C,D,E,X( 1),X( 3),X( 9),X(14));
	BODY_40_59(50,E,T,A,B,C,D,X( 2),X( 4),X(10),X(15));
	BODY_40_59(51,D,E,T,A,B,C,X( 3),X( 5),X(11),X( 0));
	BODY_40_59(52,C,D,E,T,A,B,X( 4),X( 6),X(12),X( 1));
	BODY_40_59(53,B,C,D,E,T,A,X( 5),X( 7),X(13),X( 2));
	BODY_40_59(54,A,B,C,D,E,T,X( 6),X( 8),X(14),X( 3));
	BODY_40_59(55,T,A,B,C,D,E,X( 7),X( 9),X(15),X( 4));
	BODY_40_59(56,E,T,A,B,C,D,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(57,D,E,T,A,B,C,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(58,C,D,E,T,A,B,X(10),X(12),X( 2),X( 7));
	BODY_40_59(59,B,C,D,E,T,A,X(11),X(13),X( 3),X( 8));

	BODY_60_79(60,A,B,C,D,E,T,X(12),X(14),X( 4),X( 9));
	BODY_60_79(61,T,A,B,C,D,E,X(13),X(15),X( 5),X(10));
	BODY_60_79(62,E,T,A,B,C,D,X(14),X( 0),X( 6),X(11));
	BODY_60_79(63,D,E,T,A,B,C,X(15),X( 1),X( 7),X(12));
	BODY_60_79(64,C,D,E,T,A,B,X( 0),X( 2),X( 8),X(13));
	BODY_60_79(65,B,C,D,E,T,A,X( 1),X( 3),X( 9),X(14));
	BODY_60_79(66,A,B,C,D,E,T,X( 2),X( 4),X(10),X(15));
	BODY_60_79(67,T,A,B,C,D,E,X( 3),X( 5),X(11),X( 0));
	BODY_60_79(68,E,T,A,B,C,D,X( 4),X( 6),X(12),X( 1));
	BODY_60_79(69,D,E,T,A,B,C,X( 5),X( 7),X(13),X( 2));
	BODY_60_79(70,C,D,E,T,A,B,X( 6),X( 8),X(14),X( 3));
	BODY_60_79(71,B,C,D,E,T,A,X( 7),X( 9),X(15),X( 4));
	BODY_60_79(72,A,B,C,D,E,T,X( 8),X(10),X( 0),X( 5));
	BODY_60_79(73,T,A,B,C,D,E,X( 9),X(11),X( 1),X( 6));
	BODY_60_79(74,E,T,A,B,C,D,X(10),X(12),X( 2),X( 7));
	BODY_60_79(75,D,E,T,A,B,C,X(11),X(13),X( 3),X( 8));
	BODY_60_79(76,C,D,E,T,A,B,X(12),X(14),X( 4),X( 9));
	BODY_60_79(77,B,C,D,E,T,A,X(13),X(15),X( 5),X(10));
	BODY_60_79(78,A,B,C,D,E,T,X(14),X( 0),X( 6),X(11));
	BODY_60_79(79,T,A,B,C,D,E,X(15),X( 1),X( 7),X(12));

	c->h0=(c->h0+E)&0xffffffffL;
	c->h1=(c->h1+T)&0xffffffffL;
	c->h2=(c->h2+A)&0xffffffffL;
	c->h3=(c->h3+B)&0xffffffffL;
	c->h4=(c->h4+C)&0xffffffffL;

	if (--num <= 0) break;

	A=c->h0;
	B=c->h1;
	C=c->h2;
	D=c->h3;
	E=c->h4;

	W+=SHA_LBLOCK;
	}
}

void sha1_block_data_order (SHA_CTX *c, const void *p, int num)
{
	const unsigned char *data=p;
	unsigned long A,B,C,D,E,T,l;
	unsigned long	XX0, XX1, XX2, XX3, XX4, XX5, XX6, XX7,
			XX8, XX9,XX10,XX11,XX12,XX13,XX14,XX15;

	A=c->h0;
	B=c->h1;
	C=c->h2;
	D=c->h3;
	E=c->h4;

	for (;;)
		{

	HOST_c2l(data,l); X( 0)=l;		HOST_c2l(data,l); X( 1)=l;
	BODY_00_15( 0,A,B,C,D,E,T,X( 0));	HOST_c2l(data,l); X( 2)=l;
	BODY_00_15( 1,T,A,B,C,D,E,X( 1));	HOST_c2l(data,l); X( 3)=l;
	BODY_00_15( 2,E,T,A,B,C,D,X( 2));	HOST_c2l(data,l); X( 4)=l;
	BODY_00_15( 3,D,E,T,A,B,C,X( 3));	HOST_c2l(data,l); X( 5)=l;
	BODY_00_15( 4,C,D,E,T,A,B,X( 4));	HOST_c2l(data,l); X( 6)=l;
	BODY_00_15( 5,B,C,D,E,T,A,X( 5));	HOST_c2l(data,l); X( 7)=l;
	BODY_00_15( 6,A,B,C,D,E,T,X( 6));	HOST_c2l(data,l); X( 8)=l;
	BODY_00_15( 7,T,A,B,C,D,E,X( 7));	HOST_c2l(data,l); X( 9)=l;
	BODY_00_15( 8,E,T,A,B,C,D,X( 8));	HOST_c2l(data,l); X(10)=l;
	BODY_00_15( 9,D,E,T,A,B,C,X( 9));	HOST_c2l(data,l); X(11)=l;
	BODY_00_15(10,C,D,E,T,A,B,X(10));	HOST_c2l(data,l); X(12)=l;
	BODY_00_15(11,B,C,D,E,T,A,X(11));	HOST_c2l(data,l); X(13)=l;
	BODY_00_15(12,A,B,C,D,E,T,X(12));	HOST_c2l(data,l); X(14)=l;
	BODY_00_15(13,T,A,B,C,D,E,X(13));	HOST_c2l(data,l); X(15)=l;
	BODY_00_15(14,E,T,A,B,C,D,X(14));
	BODY_00_15(15,D,E,T,A,B,C,X(15));

	BODY_16_19(16,C,D,E,T,A,B,X( 0),X( 0),X( 2),X( 8),X(13));
	BODY_16_19(17,B,C,D,E,T,A,X( 1),X( 1),X( 3),X( 9),X(14));
	BODY_16_19(18,A,B,C,D,E,T,X( 2),X( 2),X( 4),X(10),X(15));
	BODY_16_19(19,T,A,B,C,D,E,X( 3),X( 3),X( 5),X(11),X( 0));

	BODY_20_31(20,E,T,A,B,C,D,X( 4),X( 4),X( 6),X(12),X( 1));
	BODY_20_31(21,D,E,T,A,B,C,X( 5),X( 5),X( 7),X(13),X( 2));
	BODY_20_31(22,C,D,E,T,A,B,X( 6),X( 6),X( 8),X(14),X( 3));
	BODY_20_31(23,B,C,D,E,T,A,X( 7),X( 7),X( 9),X(15),X( 4));
	BODY_20_31(24,A,B,C,D,E,T,X( 8),X( 8),X(10),X( 0),X( 5));
	BODY_20_31(25,T,A,B,C,D,E,X( 9),X( 9),X(11),X( 1),X( 6));
	BODY_20_31(26,E,T,A,B,C,D,X(10),X(10),X(12),X( 2),X( 7));
	BODY_20_31(27,D,E,T,A,B,C,X(11),X(11),X(13),X( 3),X( 8));
	BODY_20_31(28,C,D,E,T,A,B,X(12),X(12),X(14),X( 4),X( 9));
	BODY_20_31(29,B,C,D,E,T,A,X(13),X(13),X(15),X( 5),X(10));
	BODY_20_31(30,A,B,C,D,E,T,X(14),X(14),X( 0),X( 6),X(11));
	BODY_20_31(31,T,A,B,C,D,E,X(15),X(15),X( 1),X( 7),X(12));

	BODY_32_39(32,E,T,A,B,C,D,X( 0),X( 2),X( 8),X(13));
	BODY_32_39(33,D,E,T,A,B,C,X( 1),X( 3),X( 9),X(14));
	BODY_32_39(34,C,D,E,T,A,B,X( 2),X( 4),X(10),X(15));
	BODY_32_39(35,B,C,D,E,T,A,X( 3),X( 5),X(11),X( 0));
	BODY_32_39(36,A,B,C,D,E,T,X( 4),X( 6),X(12),X( 1));
	BODY_32_39(37,T,A,B,C,D,E,X( 5),X( 7),X(13),X( 2));
	BODY_32_39(38,E,T,A,B,C,D,X( 6),X( 8),X(14),X( 3));
	BODY_32_39(39,D,E,T,A,B,C,X( 7),X( 9),X(15),X( 4));

	BODY_40_59(40,C,D,E,T,A,B,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(41,B,C,D,E,T,A,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(42,A,B,C,D,E,T,X(10),X(12),X( 2),X( 7));
	BODY_40_59(43,T,A,B,C,D,E,X(11),X(13),X( 3),X( 8));
	BODY_40_59(44,E,T,A,B,C,D,X(12),X(14),X( 4),X( 9));
	BODY_40_59(45,D,E,T,A,B,C,X(13),X(15),X( 5),X(10));
	BODY_40_59(46,C,D,E,T,A,B,X(14),X( 0),X( 6),X(11));
	BODY_40_59(47,B,C,D,E,T,A,X(15),X( 1),X( 7),X(12));
	BODY_40_59(48,A,B,C,D,E,T,X( 0),X( 2),X( 8),X(13));
	BODY_40_59(49,T,A,B,C,D,E,X( 1),X( 3),X( 9),X(14));
	BODY_40_59(50,E,T,A,B,C,D,X( 2),X( 4),X(10),X(15));
	BODY_40_59(51,D,E,T,A,B,C,X( 3),X( 5),X(11),X( 0));
	BODY_40_59(52,C,D,E,T,A,B,X( 4),X( 6),X(12),X( 1));
	BODY_40_59(53,B,C,D,E,T,A,X( 5),X( 7),X(13),X( 2));
	BODY_40_59(54,A,B,C,D,E,T,X( 6),X( 8),X(14),X( 3));
	BODY_40_59(55,T,A,B,C,D,E,X( 7),X( 9),X(15),X( 4));
	BODY_40_59(56,E,T,A,B,C,D,X( 8),X(10),X( 0),X( 5));
	BODY_40_59(57,D,E,T,A,B,C,X( 9),X(11),X( 1),X( 6));
	BODY_40_59(58,C,D,E,T,A,B,X(10),X(12),X( 2),X( 7));
	BODY_40_59(59,B,C,D,E,T,A,X(11),X(13),X( 3),X( 8));

	BODY_60_79(60,A,B,C,D,E,T,X(12),X(14),X( 4),X( 9));
	BODY_60_79(61,T,A,B,C,D,E,X(13),X(15),X( 5),X(10));
	BODY_60_79(62,E,T,A,B,C,D,X(14),X( 0),X( 6),X(11));
	BODY_60_79(63,D,E,T,A,B,C,X(15),X( 1),X( 7),X(12));
	BODY_60_79(64,C,D,E,T,A,B,X( 0),X( 2),X( 8),X(13));
	BODY_60_79(65,B,C,D,E,T,A,X( 1),X( 3),X( 9),X(14));
	BODY_60_79(66,A,B,C,D,E,T,X( 2),X( 4),X(10),X(15));
	BODY_60_79(67,T,A,B,C,D,E,X( 3),X( 5),X(11),X( 0));
	BODY_60_79(68,E,T,A,B,C,D,X( 4),X( 6),X(12),X( 1));
	BODY_60_79(69,D,E,T,A,B,C,X( 5),X( 7),X(13),X( 2));
	BODY_60_79(70,C,D,E,T,A,B,X( 6),X( 8),X(14),X( 3));
	BODY_60_79(71,B,C,D,E,T,A,X( 7),X( 9),X(15),X( 4));
	BODY_60_79(72,A,B,C,D,E,T,X( 8),X(10),X( 0),X( 5));
	BODY_60_79(73,T,A,B,C,D,E,X( 9),X(11),X( 1),X( 6));
	BODY_60_79(74,E,T,A,B,C,D,X(10),X(12),X( 2),X( 7));
	BODY_60_79(75,D,E,T,A,B,C,X(11),X(13),X( 3),X( 8));
	BODY_60_79(76,C,D,E,T,A,B,X(12),X(14),X( 4),X( 9));
	BODY_60_79(77,B,C,D,E,T,A,X(13),X(15),X( 5),X(10));
	BODY_60_79(78,A,B,C,D,E,T,X(14),X( 0),X( 6),X(11));
	BODY_60_79(79,T,A,B,C,D,E,X(15),X( 1),X( 7),X(12));

	c->h0=(c->h0+E)&0xffffffffL;
	c->h1=(c->h1+T)&0xffffffffL;
	c->h2=(c->h2+A)&0xffffffffL;
	c->h3=(c->h3+B)&0xffffffffL;
	c->h4=(c->h4+C)&0xffffffffL;

	if (--num <= 0) break;

	A=c->h0;
	B=c->h1;
	C=c->h2;
	D=c->h3;
	E=c->h4;

	}
}




/*
 * Function: RFC 2104 hmac_sha1 
 *
 *   unsigned char*  text          pointer to data stream
 *   int             text_len      length of data stream
 *   unsigned char*  key           pointer to authentication key
 *   int             key_len       length of authentication key
 *   unsigned char*  digest        caller digest to be filled in
 *
 */
void hmac_sha1(unsigned char* text, int text_len, unsigned char*  key, int key_len, unsigned char*  digest)
{
    SHA_CTX context;
    unsigned char k_ipad[65];    /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];    /* outer padding - key XORd with opad */
    unsigned char tk[20];		 /* L=20 for SHA1 (RFC 2141, 2. Definition of HMAC) */
    int i;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "hmac_sha1", 
				  ("text=%p, text_len=%d, key=%p, key_len=%d, digest=%p",
			      (void *)text, text_len, (void *)key, key_len, (void *)digest)
				 );

    /* if key is longer than 64 bytes reset it to key=SHA1(key) */
    if (key_len > 64) {

            SHA_CTX      tctx;

            SHA1_Init(&tctx);
            SHA1_Update(&tctx, key, key_len);
            SHA1_Final(tk, &tctx);

            key = tk;
            key_len = 20;
    }

    /*
     * the HMAC_SHA1 transform looks like:
     *
     * SHA1(K XOR opad, SHA1(K XOR ipad, text))
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
    SHA1_Init(&context);                 /* init context for 1st pass */
    SHA1_Update(&context, k_ipad, 64);   /* start with inner pad */
    SHA1_Update(&context, text, text_len);/* then text of datagram */
    SHA1_Final(digest, &context);         /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    SHA1_Init(&context);                 /* init context for 2nd
                                          * pass */
    SHA1_Update(&context, k_opad, 64);   /* start with outer pad */
    SHA1_Update(&context, digest, 20);   /* then results of 1st hash */
    SHA1_Final(digest, &context);        /* finish up 2nd pass */

   	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "hmac_sha1", ("void") );
}








