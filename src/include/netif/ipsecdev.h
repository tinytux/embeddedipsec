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

/** @file ipsecdev.h
 *  @brief Header of IPsec network adapter for lwIP
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#ifndef __IPSECDEV_H__
#define __IPSECDEV_H__


#ifdef __NO_TCPIP_STACK__		/**< define __NO_TCPIP_STACK__ to remove dependencies from the lwIP TCP/IP stack (useful for debugging in the simulator) */

#define IPSEC_HLEN  (80)		/**< default room for outer IP header, AH(24 bytes with HMAC-xxx-96)/ESP(8 bytes) data */
#define IPSEC_MTU   (1400) 		/**< maximum packet size which can be handled by ipsecdev */


#else

#include "lwip/netif.h"

#define IPSEC_HLEN	(PBUF_IP_HLEN + 24 + PBUF_TRANSPORT_HLEN)			/**< Add room for an other IP header and AH(24 bytes with HMAC-xxx-96)/ESP(8 bytes) data */
#define IPSEC_MTU 	(PBUF_POOL_BUFSIZE - PBUF_LINK_HLEN - IPSEC_HLEN) 	/**< maximum packet size which can be handled by ipsecdev */

/** Used to gather statistics, etc */
struct ipsecdev_stats
{
	u32_t sentbytes; 				/**< #number of sent bytes */
};

void ipsecdev_service(struct netif *);
err_t ipsecdev_input(struct pbuf *, struct netif *);
err_t ipsecdev_output(struct netif *, struct pbuf *, struct ip_addr *);
err_t ipsecdev_netlink_output(struct netif *netif, struct pbuf *p) ;
err_t ipsecdev_init(struct netif *);
void ipsec_set_tunnel(char *src, char *dst) ;

#endif

#endif