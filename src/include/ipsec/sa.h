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

/** @file sa.h
 *  @brief Header of Security Association management code
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 *</EM><HR>
 */

#ifndef __SA_H__
#define __SA_H__

#include "ipsec/types.h"
#include "ipsec/util.h"
#include "ipsec/ipsec.h"


#define IPSEC_MAX_SAD_ENTRIES	(10)	/**< Defines the size of SPD entries in the SPD table. */
#define IPSEC_MAX_SPD_ENTRIES	(10)	/**< Defines the size of SAD entries in the SAD table. */

#define IPSEC_FREE				(0)		/**< Tells you that an SPD entry is free */				
#define IPSEC_USED				(1)		/**< Tells you that an SPD entry is used */

#define POLICY_APPLY			(0)		/**< Defines that the policy for this SPD entry means: apply IPsec */
#define POLICY_BYPASS			(1)		/**< Defines that the policy for this SPD entry means: bypass IPsec */
#define POLICY_DISCARD			(2)		/**< Defines that the policy for this SPD entry means: the packet must be discarded */			

#define IPSEC_TUNNEL			(1)		/**< Defines TUNNEL mode as the mode the packet must be processed */
#define IPSEC_TRANSPORT			(2)		/**< Defines TRANSPORT mode as the mode the packet must be processed */

#define IPSEC_DES				(1)		/**< Defines DES as the encryption algorithm for an ESP packet */
#define IPSEC_3DES				(2)		/**< Defines 3DES as the encryption algorithm for an ESP packet */
#define IPSEC_IDEA				(3)		/**< Defines IDEA as the encryption algorithm for an ESP packet */

#define IPSEC_HMAC_MD5			(1)		/**< Defines HMAC-MD5 as the authentication algorithm for an AH or an ESP packet */
#define IPSEC_HMAC_SHA1			(2)		/**< Defines HMAC-SHA1 as the authentication algorithm for an AH or an ESP packet */

#define IPSEC_NR_NETIFS			(1)		/**< Defines the number of network interfaces. This is used to reserve space for db_netif_struct's */

typedef struct sa_entry_struct sad_entry ;					/**< Security Association Database entry */

/** \struct sa_entry_struct
 * Holds all the values used by one SA entry
 */
struct sa_entry_struct
{
	/* this are the index fields */
	__u32 		dest;				/**< IP destination address */
	__u32		dest_netaddr ;		/**< IP destination network mask */
	__u32 		spi;				/**< Security Parameter Index */
	__u8		protocol ;			/**< IPsec protocol */
	__u8		mode ;				/**< tunnel or transport mode */
	/* this fields are used to maintain the current connection */
	__u32		sequence_number ;	/**< the sequence number used to implement the anti-reply mechanism (RFC 2402, 3.3.2: initialize with 0) */
	__u8		replay_win ;		/**< reply windows size */
	__u32		lifetime ;			/**< lifetime of the SA (must be dropped if lifetime runs out) */
	__u16		path_mtu ;			/**< mean transmission unit */
	/* this fields are used for the cryptography */
	__u8		enc_alg ;						/**< encryption algorithm */
	__u8		enckey[IPSEC_MAX_ENCKEY_LEN];	/**< encryption key */
	__u8		auth_alg ;						/**< authentication algorithm */
	__u8		authkey[IPSEC_MAX_AUTHKEY_LEN] ;/**< authentication key */
	sad_entry	*next ;							/**< pointer to the next SAD entry */
	sad_entry	*prev ;							/**< pointer to the previous SAD entry */
	__u8		use_flag ;						/**< this flag defines if the SAD entry is still used or not */
	/**@todo IV for cbc-mode should be added to this structure */
	/**@todo enc_alg and auth_alg should be replced by function pointers */
};

typedef struct spd_entry_struct spd_entry ;		/**< This type hold all values used for one SPD entry */

/** \struct sa_entry_struct
 * Holds all the values used by an SPD entry
 */
struct spd_entry_struct
{
	__u32		src ;			/**< IP source address */
	__u32  		src_netaddr ;	/**< net mask for source address */
	__u32		dest ;			/**< IP destination address */
	__u32		dest_netaddr ;	/**< net mask for the destination address */
	__u8		protocol ;		/**< the transport layer protocol */
	__u16		src_port ;		/**< source port number */
	__u16		dest_port ;		/**< destination port number */
	__u8		policy ;		/**< defines how this packet must be processed */
	sad_entry 	*sa ;			/**< pointer to the associated SA */
	spd_entry	*next ;			/**< pointer to the next table entry*/
	spd_entry	*prev ;			/**< pointer to the previous table entry */
	__u8		use_flag ; 		/**< tells whether the entry is free or not */
};

/** \struct spd_table_struct
 * This structure holds pointers which together define the Security Policy Database
 */
typedef struct spd_table_struct
{
	spd_entry	*table ;		/**< Pointer to the table data. This is pointer to an array of spd_entries */
	spd_entry	*first ;		/**< Pointer to the first entry in the table */
	spd_entry	*last ;			/**< Pointer to the last entry in the table */
	int			size ;			/**< Number of usable elements in the table data */
} spd_table;

typedef struct sad_table_struct
{
	sad_entry	*table ;		/**< Pointer to the table data. This is pointer to an array of sad_entries */
	sad_entry	*first ;		/**< Pointer to the first entry in the table */
	sad_entry	*last ;			/**< Pointer to the last entry in the table */
} sad_table ;

typedef struct db_set_netif_struct
{
	spd_table	inbound_spd ;	/**< inbound SPD */
	spd_table	outbound_spd ;	/**< outbound SPD */
	sad_table	inbound_sad ;	/**< inbound SAD */
	sad_table	outbound_sad ;	/**< outbound SAD */
	__u8		use_flag ;		/**< tells whether the entry is free or not */
} db_set_netif ;


#define SPD_ENTRY(s1, s2, s3, s4, sn1, sn2, sn3, sn4, d1, d2, d3, d4, dn1, dn2, dn3, dn4, proto, src_port, dest_port, policy, sa_ptr) \
			IPSEC_IP4_ADDR_NET(s1, s2, s3, s4), \
			IPSEC_IP4_ADDR_NET(sn1, sn2, sn3, sn4), \
			IPSEC_IP4_ADDR_NET(d1, d2, d3, d4), \
			IPSEC_IP4_ADDR_NET(dn1, dn2, dn3, dn4), \
			proto, IPSEC_HTONS(src_port), IPSEC_HTONS(dest_port), policy, sa_ptr, 0, 0, \
			IPSEC_USED 			/**< helps to statically configure the SPD entries */

#define SAD_ENTRY(d1, d2, d3, d4, dn1, dn2, dn3, dn4, spi, proto, mode, enc_alg, ek1, ek2, ek3, ek4, ek5, ek6, ek7, ek8, ek9, ek10, ek11, ek12, ek13, ek14, ek15, ek16, ek17, ek18, ek19, ek20, ek21, ek22, ek23, ek24, auth_alg, ak1, ak2, ak3, ak4, ak5, ak6, ak7, ak8, ak9, ak10, ak11, ak12, ak13, ak14, ak15, ak16, ak17, ak18, ak19, ak20) \
			IPSEC_IP4_ADDR_2(d1, d2, d3, d4), \
			IPSEC_IP4_ADDR_2(dn1, dn2, dn3, dn4), \
			IPSEC_HTONL(spi), \
			proto, \ 
			mode, \
			0, 0, 0, 1450, \
			enc_alg, \
			{ek1, ek2, ek3, ek4, ek5, ek6, ek7, ek8, ek9, ek10, ek11, ek12, ek13, ek14, ek15, ek16, ek17, ek18, ek19, ek20, ek21, ek22, ek23, ek24}, \
			auth_alg, \
			{ak1, ak2, ak3, ak4, ak5, ak6, ak7, ak8, ak9, ak10, ak11, ak12, ak13, ak14, ak15, ak16, ak17, ak18, ak19, ak20}, \
			0,0, IPSEC_USED 	/**< helps to statically configure the SAD entries */

#define EMPTY_SAD_ENTRY { 0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \ 
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  0, 0, 0, 0, 0, 0, \
						  IPSEC_FREE } /**< empty, unconfigured SAD entry    */

#define EMPTY_SPD_ENTRY { 0, 0, 0, 0, 0, 0, \
					  	  0, IPSEC_FREE } /**< empty, unconfigured SPD entry */


/* SPD functions */
db_set_netif	*ipsec_spd_load_dbs(spd_entry *inbound_spd_data, spd_entry *outbound_spd_data, sad_entry *inbound_sad_data, sad_entry *outbound_sad_data) ;

ipsec_status	ipsec_spd_release_dbs(db_set_netif *dbs) ;

spd_entry *ipsec_spd_get_free(spd_table *table) ;

spd_entry *ipsec_spd_add(__u32 src, __u32 src_net, __u32 dst, 
                         __u32 dst_net, __u8 proto, __u16 src_port, 
						 __u16 dst_port, __u8 policy, spd_table *table) ;

ipsec_status ipsec_spd_del(spd_entry *entry, spd_table *table) ;

ipsec_status ipsec_spd_add_sa(spd_entry *entry, sad_entry *sa) ;

spd_entry *ipsec_spd_lookup(ipsec_ip_header *header, spd_table *table) ;

void ipsec_spd_print_single(spd_entry *entry) ;

void ipsec_spd_print(spd_table *table) ;

/* SAD functions */
sad_entry *ipsec_sad_get_free(sad_table *table) ;

sad_entry *ipsec_sad_add(sad_entry *entry, sad_table *table) ;

ipsec_status ipsec_sad_del(sad_entry *entry, sad_table *table) ;

sad_entry *ipsec_sad_lookup(__u32 dest, __u8 proto, __u32 spi, sad_table *table) ;

void ipsec_sad_print_single(sad_entry *entry) ;

void ipsec_sad_print(sad_table *table) ;

__u32 ipsec_sad_get_spi(ipsec_ip_header *header) ;

ipsec_status ipsec_spd_flush(spd_table *table, spd_entry *def_entry) ;

ipsec_status ipsec_sad_flush(sad_table *table) ;

#endif
