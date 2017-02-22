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

/** @file ipsecdev.c
 *  @brief IPsec network adapter for lwIP
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  This network interface will be inserted between the TCP/IP stack and the
 *  driver of the physical network adapter. With this, all inbound and outbound 
 *  traffic can be intercepted and forwarded to the IPsec stack if required.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  The main duty of ipsecdev device is to identify the network traffic and
 *  forward it to the appropriate protocol handler:
 *
 *     - AH/ESP => forward to ipsec_input()
 *     - IP traffic with policy BYPASS => forward to ip_input()
 *     - IP traffic with policy DISCARD, or traffic with policy APPLY but without
 *       IPsec header
 *
 *  To decide how packets must be processed, a lookup in the Security Policy
 *  Database is required. With this, all IPsec logic and IPsec related processing
 *  is put outside ipsecdev. The motivation is to separate IPsec processing from
 *  TCP/IP-Stack and network driver peculiarities. 
 *  If the ipsec stack need to be ported to an other target, all major changes
 *  can be done in this module while the rest can be left untouched.  
 *
 *  <B>NOTES:</B>
 *
 * This version of ipsecdev is able to handle traffic passed by a cs8900 driver
 * in combination with lwIP 0.6.3 STABLE. It has a similar structure as dumpdev
 * or cs9800if.
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include "lwip/mem.h"

#include "netif/ipsecdev.h"

#include "ipsec/debug.h"
#include "ipsec/ipsec.h"
#include "ipsec/util.h"
#include "ipsec/sa.h"


#define IPSECDEV_NAME0 'i'		/**< 1st letter of device name "is" */
#define IPSECDEV_NAME1 's' 		/**< 2nd letter of device name "is" */

extern sad_entry inbound_sad_config[]; /**< inbound SAD configuration data  */
extern spd_entry inbound_spd_config[]; /**< inbound SPD configuration data  */
extern sad_entry outbound_sad_config[];/**< outbound SAD configuration data */
extern spd_entry outbound_spd_config[];/**< outbound SPD configuration data */

extern db_set_netif	db_sets[];
db_set_netif 	*databases; 	/**< reference to the SPD and SA configuration*/
struct netif	mapped_netif;	/**< handler of physical output device  	*/
__u32			tunnel_src_addr;/**< tunnel source address (external address this IPsec device) */
__u32			tunnel_dst_addr;/**< tunnel destination address (external address the other IPsec tunnel endpoint) */


/**
 * This is just used to provide an consisstend interface. This function has no functionality.
 *
 * @param  netif  initialized lwIP network interface data structure of this device
 * @return void
 */
void ipsecdev_service(struct netif *netif)
{
	struct netif *i ;
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, "ipsecdev_service", ("netif=%p", (void *)netif) );
	i = netif ;
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_service", ("void") );
	return ;
}


/**
 * This function is used to process incomming IP packets.
 *
 * This function is called by the physical network driver when a new packet has been
 * received. To decide how to handle the packet, the Security Policy Database 
 * is called. ESP and AH packets are directly forwarded to ipsec_input() while other 
 * packets must pass the SPD lookup.
 *
 * @param p      pbuf containing the received packet
 * @param inp    lwIP network interface data structure for this device. The structure must be
 *               initialized with IP, netmask and gateway address.
 * @return err_t return code
 */
err_t ipsecdev_input(struct pbuf *p, struct netif *inp)
{
	int retcode;
	int payload_offset	= 0;
	int payload_size	= 0;
	spd_entry		*spd ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsecdev_input", 
				  ("p=%p, inp=%p",
			      (void *)p, (void *)inp)
				 );

	IPSEC_DUMP_BUFFER("ipsecdev_input", p->payload, 0, p->len) ;

	if(p == NULL || p->payload == NULL)
 	{
  		IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, ("Packet has no payload. Can't pass it to higher level protocol stacks."));
		pbuf_free(p) ;
	}
	else 
	{

		/* minimal sanity check of inbound data (packet buffer & IP header fields must be <= MTU) */
		if((p->tot_len > IPSEC_MTU) || (ipsec_ntohs(((ipsec_ip_header *)((unsigned char *)p->payload))->len) > IPSEC_MTU))
	 	{
	  		IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, ("Packet to long (%d > %d (IPSEC_MTU))", p->tot_len, IPSEC_MTU) );
			/* in case of error, free pbuf and return ERR_OK as lwIP does */
			pbuf_free(p) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", ("return = %d", ERR_OK) );
			return ERR_OK;
		}

		if(p->next != NULL)
	 	{
	  		IPSEC_LOG_DBG("ipsecdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, ("can not handle chained pbuf - (packet must be < %d bytes )", PBUF_POOL_BUFSIZE - PBUF_LINK_HLEN - IPSEC_HLEN) );
			/* in case of error, free pbuf and return ERR_OK as lwIP does */
			pbuf_free(p) ;
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", ("return = %d", ERR_OK) );
			return ERR_OK;
		}


		if( ((ipsec_ip_header*)(p->payload))->protocol == IPSEC_PROTO_ESP || ((ipsec_ip_header*)(p->payload))->protocol == IPSEC_PROTO_AH)
		{
			/* we got an IPsec packet which must be handled by the IPsec engine */
			retcode = ipsec_input(p->payload, p->len, (int *)&payload_offset, (int *)&payload_size, databases);

			if(retcode == IPSEC_STATUS_SUCCESS)
			{
				/** @todo Attention: the pbuf structure should be updated using pbuf_header() */
				/* remove obsolete ESP headers */
				p->payload = (unsigned char *)(p->payload) + payload_offset;
				p->len = payload_size;
				p->tot_len = payload_size;

				IPSEC_LOG_MSG("ipsecdev_input", ("fwd decapsulated IPsec packet to ip_input()") );
				retcode = ip_input(p, inp);		
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", ("retcode = %d", retcode) );
				return retcode;

			}
			else
			{
				IPSEC_LOG_ERR("ipsecdev_input", retcode, ("error on ipsec_input() processing (retcode = %d)", retcode));
				pbuf_free(p) ;
			}			
		}
		else
		{
			/* check what the policy says about non-IPsec traffic */
			spd = ipsec_spd_lookup(p->payload, &databases->inbound_spd) ;
			if(spd == NULL)
			{
				IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_NO_POLICY_FOUND, ("no matching SPD policy found")) ;
				pbuf_free(p) ;
			}
			else
			{
				switch(spd->policy)
			 	{
					case POLICY_APPLY:
						IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_APPLY, ("POLICY_APPLY: got non-IPsec packet which should be one")) ;
						pbuf_free(p) ;
						break;
					case POLICY_DISCARD:
						IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_DISCARD, ("POLICY_DISCARD: dropping packet")) ;
						pbuf_free(p) ;
						break;
					case POLICY_BYPASS:
						IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_BYPASS, ("POLICY_BYPASS: forwarding packet to ip_input")) ;
						ip_input(p, inp);
						break;
					default:
						pbuf_free(p) ;
						IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("IPSEC_STATUS_FAILURE: dropping packet")) ;
						IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
				} 
			}
		}
	}

	/* usually return ERR_OK as lwIP does */
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_input", ("retcode = %d", ERR_OK) );
	return ERR_OK;
}


/**
 * This function is used to send a packet out to the network device.
 *
 * IPsec processing for outbound traffic is done here before forwarding the IP packet 
 * to the physical network device. The SPD is queried in order to know how
 * the packet must be handled.
 *
 * @param  netif   initialized lwIP network interface data structure of this device
 * @param  p       pbuf containing a complete IP packet as payload
 * @param  ipaddr  destination IP address
 * @return err_t   status
 */
err_t ipsecdev_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	struct pbuf *p_cpy = NULL;
	int payload_size ;
	int payload_offset ;
	spd_entry *spd ;
	ipsec_status status ;
	struct ip_addr dest_addr;
	int retcode;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsecdev_output", 
				  ("netif=%p, p=%p, ipaddr=%p", (void *)netif, (void *)p, (void *)ipaddr ) 
				 );


	/* minimal sanity check of inbound data (packet buffer & IP header fields must be <= MTU) */
	if((p->tot_len > IPSEC_MTU) || (ipsec_ntohs(((ipsec_ip_header *)((unsigned char *)p->payload))->len) > IPSEC_MTU))
 	{
  		IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_DATA_SIZE_ERROR, ("Packet to long (> IPSEC_MTU) on interface '%c%c'", netif->name[0], netif->name[1]));
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("return = %d", ERR_CONN) );
		return ERR_CONN;
	}

	if(p->next != NULL)
 	{
  		IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_DATA_SIZE_ERROR, ("can not handle chained pbuf - use pbuf size of %d bytes", IPSEC_MTU));
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("return = %d", ERR_CONN) );
		return ERR_CONN;
	}

	if(p->ref != 1)
 	{
  		IPSEC_LOG_DBG("ipsecdev_output", IPSEC_STATUS_DATA_SIZE_ERROR, ("can not handle pbuf->ref != 1 - p->ref == %d", p->ref));
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("return = %d", ERR_CONN) );
		return ERR_CONN;
	}


	/** backup of physical destination IP address (inner IP header may become encrypted) */
	memcpy(&dest_addr, ipaddr, sizeof(struct ip_addr));

	/**@todo this static access to the HW device must be replaced by a more flexible method */

	/* RFC conform IPsec processing */
	spd = ipsec_spd_lookup((ipsec_ip_header*)p->payload, &databases->outbound_spd) ;
	if(spd == NULL)
	{
		IPSEC_LOG_ERR("ipsecdev_output", IPSEC_STATUS_NO_POLICY_FOUND, ("no matching SPD policy found")) ;
		/* free local pbuf here */
		pbuf_free(p);
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("retcode = %d", ERR_CONN) );
		return ERR_CONN ;
	}

	switch(spd->policy)
 	{
		case POLICY_APPLY:																		
				IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_APPLY, ("POLICY_APPLY: processing IPsec packet")) ;

				/** @todo lwIP TCP ESP outbound processing needs to add data after the original packet.
				 *        Since the lwIP TCP does leave any room after the original packet, we 
				 *        copy the packet into a larger buffer. This step can be avoided if enough
				 *        room is left after the packet when TCP allocates memory.
				 */
				p_cpy = p;
				if(spd->sa->protocol == IPSEC_PROTO_ESP)
				{
					// alloc 50 more bytes for ESP trailer and the optional ESP authentication data
				    p_cpy = pbuf_alloc(PBUF_RAW, p->len + 50, PBUF_POOL);

					if(p_cpy != NULL) {
						memcpy(p_cpy->payload, p->payload, p->len);
						p_cpy->next = NULL;
						p_cpy->len = p->len + 50;
						p_cpy->tot_len = p->tot_len + 50;
						p_cpy->ref = p->ref;
						IPSEC_LOG_MSG("ipsecdev_output", ("lwIP ESP TCP workaround: successfully allocated new pbuf (tot_len = %d)", p_cpy->tot_len) );
					}
					else {
						IPSEC_LOG_ERR("ipsecdev_output", IPSEC_AUDIT_FAILURE, ("can't alloc new pbuf for lwIP ESP TCP workaround!") ) ;
					}
				}

				status = ipsec_output(p_cpy->payload, p_cpy->len, &payload_offset, &payload_size, tunnel_src_addr, tunnel_dst_addr, spd) ;

				if(status == IPSEC_STATUS_SUCCESS)
				{
					/* adjust pbuf structure according to the real packet size */
					p_cpy->payload = (unsigned char *)(p_cpy->payload) + payload_offset;
					p_cpy->len = payload_size;
					p_cpy->tot_len = payload_size;

				  	IPSEC_LOG_MSG("ipsec_output", ("fwd IPsec packet to HW mapped device") );
					retcode = mapped_netif.output(&mapped_netif, p_cpy, (void *)&tunnel_dst_addr);
					if(spd->sa->protocol == IPSEC_PROTO_ESP) pbuf_free(p_cpy);
				}
				else {
					IPSEC_LOG_ERR("ipsec_output", status, ("error on ipsec_output() processing"));
					if(spd->sa->protocol == IPSEC_PROTO_ESP) pbuf_free(p_cpy);
					IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("retcode = %d", ERR_CONN) );
				}

				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("retcode = %d", ERR_OK) );
			return ERR_OK;
			break;
		case POLICY_DISCARD:
				IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_DISCARD, ("POLICY_DISCARD: dropping packet")) ;
			break;
		case POLICY_BYPASS:
				IPSEC_LOG_AUD("ipsecdev_output", IPSEC_AUDIT_BYPASS, ("POLICY_BYPASS: forwarding packet to ip_output")) ;
				retcode = mapped_netif.output(&mapped_netif, p, &dest_addr);
				IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("retcode = %d", retcode) );
				return retcode;
			break;
		default:
			IPSEC_LOG_ERR("ipsecdev_input", IPSEC_STATUS_FAILURE, ("POLICY_DIRCARD: dropping packet")) ;
			IPSEC_LOG_AUD("ipsecdev_input", IPSEC_AUDIT_FAILURE, ("unknown Security Policy: dropping packet")) ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_output", ("return = %d", ERR_CONN) );
	return ERR_CONN;
}


/**
 * This function is used to send a packet directly out of the network device.
 *
 * The packet is directly sent as-is the network device output function.
 * It is used to serve ARP traffic.
 *
 * @param  netif  initialized lwIP network interface data structure of this device
 * @param  p      pbuf containing a complete IP packet as payload
 * @return err_t  status
 */
err_t ipsecdev_netlink_output(struct netif *netif, struct pbuf *p)
{
	int retcode;
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsecdev_netlink_output", 
				  ("netif=%p, p=%d", (void *)netif, (void *)p ) 
				 );
	IPSEC_LOG_MSG("ipsecdev_netlink_output", ("fwd from interface '%c%c' to real HW linkoutput",  netif->name[0], netif->name[1]) );

	retcode = mapped_netif.linkoutput(&mapped_netif, p);
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_netlink_output", ("retcode = %d", retcode) );
	return retcode; 
}


/**
 * Initialize the ipsec network device
 *
 * This function must be called prior to any other operation with this device.
 *
 * @param  netif  lwIP network interface data structure for this device. The structure must be
 *                initialized with IP, netmask and gateway address.
 * @return err_t  return code
 */
err_t ipsecdev_init(struct netif *netif)
{
	struct ipsecdev_stats *ipsecdev_stats;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsecdev_init", 
				  ("netif=%p", (void *)netif ) 
				 );


	ipsecdev_stats = mem_malloc(sizeof(struct ipsecdev_stats));
	if (ipsecdev_stats == NULL)
	{
  		IPSEC_LOG_DBG("ipsecdev_init", IPSEC_STATUS_DATA_SIZE_ERROR, ("out of memory for ipsecdev_stats"));
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_init", ("retcode = %d", ERR_MEM) );
		return ERR_MEM;
	}

	/* set the name of this interface */
	netif->name[0] = IPSECDEV_NAME0;
	netif->name[1] = IPSECDEV_NAME1;

	/* use the same output function for all operations */
	netif->output = (void *)ipsecdev_output;				/* usually called if the IP module wants to send data */
	netif->linkoutput = (void *)ipsecdev_netlink_output;	/* usually called if the ARP module wants to send data "as-is" */

	/**@todo this should be somewhere else */
	/* initialize the db_sets structure */
	memset(db_sets, 0, IPSEC_NR_NETIFS*sizeof(db_set_netif)) ;

	/* swap output devices */
	/**@todo selecting the right interface for mapping must be replaced by an more generic method */
	/* save mapped netif */
	memcpy(&mapped_netif, netif_list, sizeof(struct netif)) ;
	netif_list->output = (void *)ipsecdev_output;

	/* setup ipsec databases/configuration */
	databases = ipsec_spd_load_dbs(inbound_spd_config, outbound_spd_config, inbound_sad_config, outbound_sad_config) ;
	if (databases == NULL)
	{
		IPSEC_LOG_ERR("ipsecdev_init", -1, ("not able to load SPD and SA configuration for ipsec device")) ;
	}

	ipsecdev_stats->sentbytes = 0;			/* reset statistic */
	netif->state = ipsecdev_stats;			/* assign statistic */
  	netif->mtu = 1500;						/* set MTU */
	netif->flags = NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;	/* device is always connected and supports broadcasts */
  	netif->hwaddr_len = 6;					/* set hardware address (MAC address) */

	/**@todo MAC addresses should be set somewhere else */
#ifdef PHYCORE167HSE 
	netif->hwaddr_len = 6;					/* set hardware address (MAC address) */
	netif->hwaddr[0] = 0xA4;
	netif->hwaddr[1] = 0xB4;
	netif->hwaddr[2] = 0xC4;
	netif->hwaddr[3] = 0xD4;
	netif->hwaddr[4] = 0xE4;
	netif->hwaddr[5] = 0xF4;
#else
	netif->hwaddr_len = 6;					/* set hardware address (MAC address) */
	netif->hwaddr[0] = 0xA3;
	netif->hwaddr[1] = 0xB3;
	netif->hwaddr[2] = 0xC3;
	netif->hwaddr[3] = 0xD3;
	netif->hwaddr[4] = 0xE3;
	netif->hwaddr[5] = 0xF3;
#endif

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsecdev_init", ("retcode = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS;
}

/**
 * Setter function for tunnel source and destination address
 *
 * @param  src  source address as string (i.g. "192.168.1.3")
 * @param  dst  destination address as string (i.g. "192.168.1.5")
 * @return void
 */
void ipsec_set_tunnel(char *src, char *dst)
{
	tunnel_src_addr = ipsec_inet_addr(src) ;
	tunnel_dst_addr = ipsec_inet_addr(dst) ;
	return ;
}
