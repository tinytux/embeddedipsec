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

/** @file esp.h
 *  @brief Header for the Encapsulating Security Payload module
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#ifndef __ESP_H__
#define __ESP_H__

#include "ipsec/sa.h"

#define IPSEC_ESP_IV_SIZE		(8)			/**< Defines the size (in bytes) of the Initialization Vector used by DES and 3DES */
#define IPSEC_ESP_SPI_SIZE		(4)			/**< Defines the size (in bytes) of the SPI of an ESP packet */
#define IPSEC_ESP_SEQ_SIZE		(4)			/**< Defines the size (in bytes) of the Sequence Number of an ESP packet */
#define IPSEC_ESP_HDR_SIZE		(IPSEC_ESP_SPI_SIZE+IPSEC_ESP_SEQ_SIZE)	/**< Defines the size (in bytes) of the ESP header. Actually it defines just the size of the header which is located in */


typedef struct ipsec_esp_header_struct
{
	__u32 	spi;			/**< Security Parameters Index      */
	__u32	sequence_number;/**< Sequence number                */
} ipsec_esp_header;


typedef struct esp_packet_struct
{
	__u32 	spi ;					/**< Security Parameters Index */
	__u32	sequence ;				/**< Sequence number */
	__u8	data[1] ;				/**< start of data, usually start of the IV */
} esp_packet ;


extern __u32 ipsec_esp_bitmap; 	
extern __u32 ipsec_esp_lastSeq;

ipsec_status ipsec_esp_decapsulate(ipsec_ip_header *packet, int *offset, int *len, sad_entry *sa) ;
ipsec_status ipsec_esp_encapsulate(ipsec_ip_header *packet, int *offset, int *len, sad_entry *sa, __u32 src_addr, __u32 dest_addr) ;

#endif
