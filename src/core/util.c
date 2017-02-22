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

/** @file util.c
 *  @brief A collection of common helper functions and macros 
 *         used everywhere in the IPsec library
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *  The following functions are implemented in this module:
 *   - logging
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the lwIP project by Adam Dunkels and others<BR>
 * Copyright (c) 2001, 2002 Swedish Institute of Computer Science.<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>
#include <ctype.h>

#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/debug.h"

/**
 * Prints the header of an IP packet
 *
 * @param header pointer to an IP header
 * @return void
 */
void ipsec_print_ip(ipsec_ip_header *header)
{
	char	log_message[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 	port[4+1] ;
	char	src[15+1] ;
	char	dest[15+1] ;
	__u16	len ;

	strcpy(src, ipsec_inet_ntoa(header->src)) ;
	strcpy(dest, ipsec_inet_ntoa(header->dest)) ;

	len = ipsec_ntohs(header->len) ;

	switch(header->protocol)
	{
		case IPSEC_PROTO_TCP:
			strcpy(port, " TCP") ;
			break ;
		case IPSEC_PROTO_UDP:
			strcpy(port, " UDP") ;
			break ;
		case IPSEC_PROTO_AH:
			strcpy(port, "  AH") ;
			break ;
		case IPSEC_PROTO_ESP:
			strcpy(port, " ESP") ;
			break ;
		case IPSEC_PROTO_ICMP:
			strcpy(port, "ICMP") ;
			break ;
		default:
			strcpy(port, "????") ;
	}

	sprintf(log_message, "src: %15s dest: %15s protocol: %3s size: %d", src, dest, port, len) ;
	printf("          %s\n", log_message) ;

	return ;
}


/**
 * Converts an IP address from the dotted notation into a 32-bit network order
 *
 * @param	cp				IP address in dotted notation
 * @return	 				address in network order
 * @return	IP_ADDR_NONE 	on failure the return value has all bits set to 1
 */
__u32 ipsec_inet_addr(const char *cp)
{
	struct ipsec_in_addr val;

    if (ipsec_inet_aton(cp, &val)) {
    	return (val.s_addr);
    }
    return (IPSEC_IP_ADDR_NONE);
}

/**
 * Converts an IP address from dotted notation into a 32-bit value. This function is used
 * by inet_addr().
 *
 * @param	cp		IP address in dotted notation
 * @param 	addr	binary IP address
 * @return	1		Address is valid
 * @return	0		Address is not valid
 */
int ipsec_inet_aton(const char *cp, struct ipsec_in_addr *addr)
 {
     __u32 val;
     int base, n;
     char c;
     static __u32 huge parts[4];
     static __u32 huge *pp ;
	 
	 pp = parts;

     c = *cp;

     for (;;) {
         /*
          * Collect number up to ``.''.
          * Values are specified as for C:
          * 0x=hex, 0=octal, isdigit=decimal.
          */
         if (!isdigit(c))
             return (0);
         val = 0; base = 10;
         if (c == '0') {
             c = *++cp;
             if (c == 'x' || c == 'X')
                 base = 16, c = *++cp;
             else
                 base = 8;
         }
         for (;;) {
		 /*** NS: made it a bit weaker, orig: if (isascii(c) && isdigit(c)) {*/
             if (isdigit(c)) {
                 val = (val * base) + (c - '0');
                 c = *++cp;
				 /*** NS: made it a bit weaker, orig: } else if (base == 16 && isalpha(c) && isxdigit(c)) {*/
             } else if (base == 16 && isxdigit(c)) {
                 val = (val << 4) |
                     (c + 10 - (islower(c) ? 'a' : 'A'));
                 c = *++cp;
             } else
             break;
         }
         if (c == '.') {
             /*
              * Internet format:
              *  a.b.c.d
              *  a.b.c   (with c treated as 16 bits)
              *  a.b (with b treated as 24 bits)
              */
			  /*** NS: added sizeof() */
             if (pp >= parts + 3)
                 return (0);
             *pp++ = val;
             c = *++cp;
         } else
             break;
     }
     /*
      * Check for trailing characters.
      */
     if (c != '\0' && (!isalpha(c) || !isspace(c)))
         return (0);
     /*
      * Concoct the address according to
      * the number of parts specified.
      */
     n = (int) (pp - parts + 1);
     switch (n) {

     case 0:
         return (0);     /* initial nondigit */

     case 1:             /* a -- 32 bits */
         break;

     case 2:             /* a.b -- 8.24 bits */
         if (val > 0xffffff)
             return (0);
         val |= parts[0] << 24;
         break;

     case 3:             /* a.b.c -- 8.8.16 bits */
         if (val > 0xffff)
             return (0);
         val |= (parts[0] << 24) | (parts[1] << 16);
         break;

     case 4:             /* a.b.c.d -- 8.8.8.8 bits */
         if (val > 0xff)
             return (0);
         val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
         break;
     }
     if (addr)
         addr->s_addr = ipsec_htonl(val);
     return (1);
 }

/**
 * Converts an binary IP address to a dotted notation
 * Beware that this function is not reentrant.
 * 
 * @param addr	binary IP address
 * @return pointer to the character string representing the dotted notation
 */
__u8 *ipsec_inet_ntoa(__u32 addr)
{
  static __u8 str[16];
  __u8 inv[3];
  __u8 *rp;
  __u8 *ap;
  __u8 rem;
  __u8 n;
  __u8 i;

  rp = str;
  ap = (__u8 *)&addr;
  for(n = 0; n < 4; n++) {
    i = 0;
    do {
      rem = (__u8)(*ap % (__u8)10);
      *ap /= (__u8)10;
      inv[i++] = '0' + rem;
    } while(*ap);
    while(i--)
      *rp++ = inv[i];
    *rp++ = '.';
    ap++;
  }
  *--rp = 0;
  return str;
}

/**
 * Converts short types from host to network order
 *
 * @param n short value in host order
 * @return short value in network order
 */
__u16 ipsec_htons(__u16 n)
{
  return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
}

/**
 * Converts short types from network to host order
 *
 * @param n short value in network order
 * @return short value in host order
 */
__u16 ipsec_ntohs(__u16 n)
{
  return ipsec_htons(n);
}

/**
 * Converts long types from host to network order
 *
 * @param n long value in host order
 * @return long value in network order
 */
__u32 ipsec_htonl(__u32 n)
{
  return ((n & 0xff) << 24) |
    ((n & 0xff00) << 8) |
    ((n & 0xff0000) >> 8) |
    ((n & 0xff000000) >> 24);
}

/**
 * Converts long types from network to host order
 *
 * @param n long value in network order
 * @return long value in host order
 */
__u32 ipsec_ntohl(__u32 n)
{
  return ipsec_htonl(n);
}

/**
 * helper function to calculate the IP header checksum
 *
 * @param len 		length of the buffer
 * @param dataptr	pointer the buffer
 * @return 16-bit value of the checksum
 */
static __u16 chksum(void *dataptr, int len)
{
  __u32 acc;

  for(acc = 0; len > 1; len -= 2) {
      /*    acc = acc + *((u16_t *)dataptr)++;*/
    acc += *(__u16 *)dataptr;
    dataptr = (void *)((__u16 *)dataptr + 1);
  }

  /* add up any odd byte */
  if (len == 1) {
    acc += ipsec_htons((__u16)((*(__u8 *)dataptr) & 0xff) << 8);
  } else {

  }
  acc = (acc >> 16) + (acc & 0xffffUL);

  if ((acc & 0xffff0000) != 0) {
    acc = (acc >> 16) + (acc & 0xffffUL);
  }

  return (__u16)acc;
}

/**
 * calculates the checksum of the IP header
 * 
 * @param dataptr	pointer to the buffer
 * @param len		length of the buffer
 * @return 16-bit value of the checksum
 */
__u16 ipsec_ip_chksum(void *dataptr, __u16 len)
{
  __u32 acc;

  acc = chksum(dataptr, len);
  while (acc >> 16) {
    acc = (acc & 0xffff) + (acc >> 16);
  }
  return ~(acc & 0xffff);
}


#ifdef IPSEC_TRACE
int __ipsec_trace_indication = 0;		/**< dummy variable to avoid compiler warnings */
int __ipsec_trace_indication__pos = 0;	/**< dummy variable to avoid compiler warnings */
#endif

/**
 * Dump (print) a memory location
 *
 * @param prefix print this text at the beginning of each line
 * @param data pointer the buffer which should be printed
 * @param offs offset from the buffer's start address
 * @param length number of bytes to be printed
 *              initialized with IP, netmask and gateway address.
 * @return void
 */
void ipsec_dump_buffer(char *prefix, unsigned char *data, int offs, int length) 
{
	unsigned char *ptr;
	unsigned char *tmp_ptr;
	int i;

	printf("%sDumping %d bytes from address 0x%08Lx using an offset of %d bytes\n", prefix, length, data, offs); 
	if(length == 0) {
		printf("%s => nothing to dump\n", prefix);
		return;
	}

	for(ptr = (data + offs); ptr < (data + offs + length); ptr++) {
		if(((ptr - (data + offs)) % 16) == 0) printf("%s%08Lx:", prefix, ptr);
		printf(" %02X", *ptr);
		if(((ptr - (data + offs)) % 16) == 15) {
			printf(" :");
			for(tmp_ptr = (ptr - 15); tmp_ptr < ptr; tmp_ptr++) {
				if(*tmp_ptr < 32) printf("."); else printf("%c", *tmp_ptr);
			}
		printf("\n");
		}
	}

	if((length % 16) > 0) {
		for(i = 0; i < (16 - (length % 16)); i++) {
			printf("   ");
		}

		printf(" :");
		for(tmp_ptr = ((data + offs + length) - (length % 16)); tmp_ptr < (data + offs + length); tmp_ptr++) {
			if(*tmp_ptr < 32) printf("."); else printf("%c", *tmp_ptr);
		}
	}

	printf("\n");
}


/**
 * Verify the sequence number of the AH packet is inside the window (defined as IPSEC_SEQ_MAX_WINDOW)
 * Note: this function does NOT update the lastSeq variable and may
 *       safely be called prior to IVC check.
 *
 * @param  seq       sequence number of the current packet
 * @param  lastSeq   sequence number of the last known packet
 * @param  bitField  field used to verify resent data within the window
 * @return IPSEC_AUDIT_SUCCESS if check passed (packet allowed)
 * @return IPSEC_AUDIT_SEQ_MISMATCH if check failed (packet disallowed)
 */
ipsec_audit ipsec_check_replay_window(__u32 seq, __u32 lastSeq, __u32 bitField) 
{
    __u32 diff;

    if(seq == 0) return IPSEC_AUDIT_SEQ_MISMATCH;    /* first == 0 or wrapped */
    
    if(seq > lastSeq) 					/* new larger sequence number  */
    {  
        diff = seq - lastSeq;

	    /* only accept new number if delta is not > IPSEC_SEQ_MAX_WINDOW */
	    if(diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH;
    }
    else {								/* new smaller sequence number */
    	diff = lastSeq - seq;

	    /* only accept new number if delta is not > IPSEC_SEQ_MAX_WINDOW */
	    if(diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH;

	    /* already seen */
	    if(bitField & ((__u32)1 << diff)) return IPSEC_AUDIT_SEQ_MISMATCH; 
    }
    
    return IPSEC_AUDIT_SUCCESS;
}


/**
 * Verify and update the sequence number.
 * Note: this function is UPDATING the lastSeq variable and must be called
 *       only AFTER checking the IVC.
 *
 * This  code  is  based  on  RFC2401,  Appendix  C  --  Sequence  Space  Window  Code  Example 
 *
 * @param  seq       sequence number of the current packet
 * @param  lastSeq   pointer to sequence number of the last known packet
 * @param  bitField  pointer to field used to verify resent data within the window
 * @return IPSEC_AUDIT_SUCCESS if check passed (packet allowed)
 * @return IPSEC_AUDIT_SEQ_MISMATCH if check failed (packet disallowed)
 */
ipsec_audit ipsec_update_replay_window(__u32 seq, __u32 *lastSeq, __u32 *bitField) 
{
    __u32 diff;

    if (seq == 0) return IPSEC_AUDIT_SEQ_MISMATCH;     	/* first == 0 or wrapped 	*/
    if (seq > *lastSeq) {               		/* new larger sequence number 		*/
        diff = seq - *lastSeq;
        if (diff < IPSEC_SEQ_MAX_WINDOW) {  	/* In window */
            *bitField <<= diff;
            *bitField |= 1;	         			/* set bit for this packet 			*/
        } else *bitField = 1;					/* This packet has a "way larger" 	*/
        *lastSeq = seq;
        return IPSEC_AUDIT_SUCCESS;  			/* larger is good */
    }
    diff = *lastSeq - seq;
    if (diff >= IPSEC_SEQ_MAX_WINDOW) return IPSEC_AUDIT_SEQ_MISMATCH; /* too old or wrapped */
    if (*bitField & ((__u32)1 << diff)) return IPSEC_AUDIT_SEQ_MISMATCH; /* already seen 	*/
    *bitField |= ((__u32)1 << diff);      		/* mark as seen 			*/
    return IPSEC_AUDIT_SUCCESS;           		/* out of order but good 	*/
}


