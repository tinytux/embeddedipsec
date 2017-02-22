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

/** @file esp.c
 *  @brief This module contains the Encapsulating Security Payload code
 *
 *  @author  Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  <B>IMPLEMENTATION:</B>
 * All functions work in-place (i.g. mainipulate directly the original
 * packet without copying any data). For the encapsulation routine,
 * the caller must ensure that space for the new IP and ESP header are
 * available in front of the packet:
 *
 *  <pre>
 *                              | pointer to packet header
 *     ________________________\/________________________________________________
 *    |          ¦       ¦      ¦                             ¦ padd       ¦ ev. |
 *    | Ethernet ¦ newIP ¦ ESP  ¦   original (inner) packet   ¦ next-proto ¦ ICV |
 *    |__________¦_______¦______¦_____________________________¦____________¦_____|
 *    ¦                         ¦                             ¦                  ¦ 
 *    ¦<-room for new headers-->¦                             ¦<-   room tail  ->¦ 
 *  </pre>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include <string.h>

#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/debug.h"

#include "ipsec/sa.h"
#include "ipsec/des.h"
#include "ipsec/md5.h"
#include "ipsec/sha1.h"

#include "ipsec/esp.h"


__u32 ipsec_esp_bitmap 	= 0;        		/**< save session state to detect replays - must be 32 bits. 
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */
__u32 ipsec_esp_lastSeq	= 0;         		/**< save session state to detect replays
											 *   Note: must be initialized with zero (0x00000000) when
											 *         a new SA is established! */



/**
 * Returns the number of padding needed for a certain ESP packet size 
 *
 * @param	len		the length of the packet
 * @return	the length of padding needed
 */
__u8 ipsec_esp_get_padding(int len)
{
	int padding ;

	for(padding = 0; padding < 8; padding++)
		if(((len+padding) % 8) == 0)
			break ;
	return padding ;
}

/**
 * Decapsulates an IP packet containing an ESP header.
 *
 * @param	packet 	pointer to the ESP header
 * @param 	offset	pointer to the offset which is passed back
 * @param 	len		pointer to the length of the decapsulated packet
 * @param 	sa		pointer to the SA
 * @return IPSEC_STATUS_SUCCESS 	if the packet could be decapsulated properly
 * @return IPSEC_STATUS_FAILURE		if the SA's authentication algorithm was invalid or if ICV comparison failed
 * @return IPSEC_STATUS_BAD_PACKET	if the decryption gave back a strange packet
 */
ipsec_status ipsec_esp_decapsulate(ipsec_ip_header *packet, int *offset, int *len, sad_entry *sa)
 {
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;			/* by default, the return value is undefined */
 	__u8 				ip_header_len ;
	int					local_len ;
	int					payload_offset ;
	int					payload_len ;
	ipsec_ip_header		*new_ip_packet ;
	esp_packet			*esp_header ;			
	char 				cbc_iv[IPSEC_ESP_IV_SIZE] ;
	unsigned char 		digest[IPSEC_MAX_AUTHKEY_LEN];

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_esp_decapsulate", 
				  ("packet=%p, *offset=%d, *len=%d sa=%p",
			      (void *)packet, *offset, *len, (void *)sa)
				 );
	
	ip_header_len = (packet->v_hl & 0x0f) * 4 ;
	esp_header = (esp_packet*)(((char*)packet)+ip_header_len) ; 
	payload_offset = ip_header_len + IPSEC_ESP_SPI_SIZE + IPSEC_ESP_SEQ_SIZE ;
	payload_len = ipsec_ntohs(packet->len) - ip_header_len - IPSEC_ESP_HDR_SIZE ;


	if(sa->auth_alg != 0)
	{

		/* preliminary anti-replay check (without updating the global sequence number window)     */
		/* This check prevents useless ICV calculation if the Sequence Number is obviously wrong  */
		ret_val = ipsec_check_replay_window(ipsec_ntohl(esp_header->sequence), ipsec_esp_lastSeq, ipsec_esp_bitmap);
		if(ret_val != IPSEC_AUDIT_SUCCESS)
		{
			IPSEC_LOG_AUD("ipsec_esp_decapsulate", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", ipsec_esp_lastSeq, ipsec_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
			return ret_val;
		}

		/* recalcualte ICV */
		switch(sa->auth_alg) {

		case IPSEC_HMAC_MD5: 
			hmac_md5((unsigned char *)esp_header, payload_len-IPSEC_AUTH_ICV+IPSEC_ESP_HDR_SIZE,
			         (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		case IPSEC_HMAC_SHA1: 
			hmac_sha1((unsigned char *)esp_header, payload_len-IPSEC_AUTH_ICV+IPSEC_ESP_HDR_SIZE,
			          (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		default:
			IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("unknown HASH algorithm for this ESP")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
		}
		
		/* compare ICV */
		if(memcmp(((char*)esp_header)+IPSEC_ESP_HDR_SIZE+payload_len-IPSEC_AUTH_ICV, digest, IPSEC_AUTH_ICV) != 0) {
			IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("ESP ICV does not match")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
		}

		/* reduce payload by ICV */
		payload_len -= IPSEC_AUTH_ICV ;

		/* post-ICV calculationn anti-replay check (this call will update the global sequence number window) */
		ret_val = ipsec_update_replay_window(ipsec_ntohl(esp_header->sequence), (__u32 *)&ipsec_esp_lastSeq, (__u32 *)&ipsec_esp_bitmap);
		if(ret_val != IPSEC_AUDIT_SUCCESS)
		{
			IPSEC_LOG_AUD("ipsec_esp_decapsulate", IPSEC_AUDIT_SEQ_MISMATCH, ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", ipsec_esp_lastSeq, ipsec_ntohl(esp_header->sequence), IPSEC_SEQ_MAX_WINDOW) );
			return ret_val;
		}

	}


	/* decapsulate the packet according the SA */
	if(sa->enc_alg == IPSEC_3DES)
	{
		/* copy IV from ESP payload */
		memcpy(cbc_iv, ((char*)packet)+payload_offset, IPSEC_ESP_IV_SIZE);

		/* decrypt ESP packet */
		cipher_3des_cbc(((char*)packet)+payload_offset + IPSEC_ESP_IV_SIZE, payload_len-IPSEC_ESP_IV_SIZE, (unsigned char *)sa->enckey, (char*)&cbc_iv,
						 DES_DECRYPT, ((char*)packet)+payload_offset + IPSEC_ESP_IV_SIZE);
	}

	*offset = payload_offset+IPSEC_ESP_IV_SIZE ;

	new_ip_packet = (ipsec_ip_header*)(((char*)packet) + payload_offset + IPSEC_ESP_IV_SIZE) ;
	local_len = ipsec_ntohs(new_ip_packet->len) ;

	if( (local_len < IPSEC_MIN_IPHDR_SIZE) || (local_len > IPSEC_MTU))
	{
		IPSEC_LOG_ERR("ipsec_esp_decapsulate", IPSEC_STATUS_FAILURE, ("decapsulated strange packet")) ;
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_BAD_PACKET) );
		return IPSEC_STATUS_BAD_PACKET;
	}
	*len = local_len ;

	sa->sequence_number++ ;

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_decapsulate", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
 }

/**
 * Encapsulates an IP packet into an ESP packet which will again be added to an IP packet.
 * 
 * @param	packet		pointer to the IP packet 
 * @param 	offset		pointer to the offset which will point to the new encapsulated packet
 * @param 	len			pointer to the length of the new encapsulated packet
 * @param 	sa			pointer to the SA
 * @param 	src_addr	source IP address of the outer IP header
 * @param 	dest_addr	destination IP address of the outer IP header 
 * @return 	IPSEC_STATUS_SUCCESS		if the packet was properly encapsulated
 * @return 	IPSEC_STATUS_TTL_EXPIRED	if the TTL expired
 * @return  IPSEC_STATUS_FAILURE		if the SA contained a bad authentication algorithm
 */
 ipsec_status ipsec_esp_encapsulate(ipsec_ip_header *packet, int *offset, int *len, sad_entry *sa, __u32 src_addr, __u32 dest_addr)
 {
	int ret_val = IPSEC_STATUS_NOT_INITIALIZED;			/* by default, the return value is undefined */
	__u8				tos ;
	int					inner_len ;
	int					payload_offset ;
	int					payload_len ;
	__u8				padd_len ;
	__u8				*pos ;
	__u8				padd ;
	ipsec_ip_header		*new_ip_header ;
	ipsec_esp_header	*new_esp_header ;
	unsigned char 		iv[IPSEC_ESP_IV_SIZE] = {0xD4, 0xDB, 0xAB, 0x9A, 0x9A, 0xDB, 0xD1, 0x94} ;
	unsigned char 		cbc_iv[IPSEC_ESP_IV_SIZE] ;
	unsigned char 		digest[IPSEC_MAX_AUTHKEY_LEN];

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_esp_encapsulate", 
				  ("packet=%p, *offset=%d, *len=%d, sa=%p, src_addr=%lu, dest_addr=%lu",
			      (void *)packet, *offset, *len, (void *)sa, src_addr, dest_addr)
				 );

	/* set new packet header pointers */
	new_ip_header = (ipsec_ip_header*)(((char*)packet) - IPSEC_ESP_IV_SIZE - IPSEC_ESP_HDR_SIZE - IPSEC_MIN_IPHDR_SIZE) ;
	new_esp_header = (ipsec_esp_header*)(((char*)packet) - IPSEC_ESP_IV_SIZE - IPSEC_ESP_HDR_SIZE) ;
	payload_offset = (((char*)packet) - ((char*)new_ip_header)) ;

	inner_len = ipsec_ntohs(packet->len) ;

	/* save TOS from inner header */
	tos = packet->tos ;

	/** @todo fix TTL update and checksum calculation */
	// packet->ttl--;
	// packet->chksum = ip_chksum(packet, sizeof(ip_header));
	if (packet->ttl == 0)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_encapsulate", ("return = %d", IPSEC_STATUS_TTL_EXPIRED) );
		return IPSEC_STATUS_TTL_EXPIRED;
	}
	
 	/* add padding if needed */
	padd_len = ipsec_esp_get_padding(inner_len+2) ;	
	pos = ((char*)packet)+inner_len ;
	if(padd_len != 0)
	{
		padd = 1 ;
		while(padd <= padd_len)
			*pos++ = padd++ ;
	}
	
	/* append padding length and next protocol field to the payload */
	*pos++ = padd_len ;
	/* in tunnel mode the next protocol field is always IP */
	*pos = 0x04 ; 

	payload_len = inner_len+IPSEC_ESP_HDR_SIZE+IPSEC_ESP_IV_SIZE + padd_len + 2 ;

	/* decapsulate the packet according the SA */
	if(sa->enc_alg == IPSEC_3DES)
	{
		/* get IV from SA */
		memcpy(cbc_iv, iv, IPSEC_ESP_IV_SIZE);

		/* encrypt ESP packet */
		cipher_3des_cbc((__u8 *)packet, inner_len+padd_len+2, (__u8 *)sa->enckey, (__u8 *)&cbc_iv,
						 DES_ENCRYPT, (__u8 *)packet);
	}

	/* insert IV in fron of packet */
	memcpy( ((char*)packet)-IPSEC_ESP_IV_SIZE, iv, IPSEC_ESP_IV_SIZE) ;

	/* setup ESP header */
	new_esp_header->spi = sa->spi;
	/** 1st packet needs to be sent out with squ = 1 */
	sa->sequence_number++ ;
	new_esp_header->sequence_number = ipsec_htonl(sa->sequence_number) ;

	/* calculate the ICV if needed */
	if(sa->auth_alg != 0)
	{
		/* recalcualte ICV */
		switch(sa->auth_alg) {

		case IPSEC_HMAC_MD5: 
			hmac_md5((unsigned char *)new_esp_header, payload_len,
			         (unsigned char *)sa->authkey, IPSEC_AUTH_MD5_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		case IPSEC_HMAC_SHA1: 
			hmac_sha1((unsigned char *)new_esp_header, payload_len,
			          (unsigned char *)sa->authkey, IPSEC_AUTH_SHA1_KEY_LEN, (unsigned char *)&digest);
			ret_val = IPSEC_STATUS_SUCCESS; 
			break;
		default:
			IPSEC_LOG_ERR("ipsec_esp_encapsulate", IPSEC_STATUS_FAILURE, ("unknown HASH algorithm for this ESP")) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_encapsulate", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE;
		}
		
		/* set ICV */
		memcpy(((char*)new_esp_header)+payload_len, digest, IPSEC_AUTH_ICV);
		
		/* increase payload by ICV */
		payload_len += IPSEC_AUTH_ICV ;
	}

	/* setup IP header */
	new_ip_header->v_hl = 0x45 ;
	new_ip_header->tos = tos ;
	//new_ip_header->len = ipsec_htons(inner_len+padd_len+2+IPSEC_ESP_IV_SIZE+IPSEC_ESP_HDR_SIZE+IPSEC_MIN_IPHDR_SIZE) ; /**@todo when auth enables the size changes */
	new_ip_header->len = ipsec_htons(payload_len+ IPSEC_MIN_IPHDR_SIZE); 
	new_ip_header->id = 1000 ;	/**@todo id must be generated properly and incremented */
	new_ip_header->offset = 0 ;
	new_ip_header->ttl = 64 ;
	new_ip_header->protocol = IPSEC_PROTO_ESP ;
	new_ip_header->chksum = 0 ;
	new_ip_header->src = src_addr ;
	new_ip_header->dest = dest_addr ;

	/* set checksum */
	new_ip_header->chksum = ipsec_ip_chksum(new_ip_header, sizeof(ipsec_ip_header)) ;

	/* setup return values */
	*offset = payload_offset*(-1) ;
	*len = payload_len + IPSEC_MIN_IPHDR_SIZE ;

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_esp_encapsulate", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
 }

