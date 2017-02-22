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
/** @file dumpdev.c
 *  @brief Dummy network adapter that will simulate a network adapter and dump all packets
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 * 	This simple dummy network interface can be used to debug ipsec and the lwIP stack
 *  by injecting a sequence of previously dumped packets. All INBOUND (from the
 *  dumpdev into higher protocol layers such as ipsec or TCP/IP) and OUTBOUND
 *  (data coming from the TCP/IP and ipsec stack, ready to be sent out i.g. in an Ethernet
 *  frame over the wire) packets are dumped using the printf() function. 
 *  This allows a simple verification of the fed traffic.
 * 
 *  <B>IMPLEMENTATION:</B>
 *
 *  A sequence of previously dumped packets can be used as input. An example of
 *  a ping sequence can be found in "dumpdev-pingdata.h". 
 *
 *  <B>NOTES:</B>
 *
 *  It may be useful to modify the dumpdev code in order to allow automatic verification
 *  of the outbound traffic.
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#include "lwip/mem.h"
#include "netif/etharp.h"
#include "netif/dumpdev.h"

#include "ipsec/debug.h"
#include "ipsec/util.h"

#define DUMPDEV_NAME0 'd'	/**< 1st letter of device name "dp" */
#define DUMPDEV_NAME1 'p'	/**< 1st letter of device name "dp" */


/** If defined, response of upper level stacks (ipsec/TCP/IP) will not be
	verified against the dumped response packets
	@todo this feature is not implemented
 */
#define DUMPDEV_IGNORE_RESPONSE

/** If DUMPDEV_USE_PING_DATA defined, a recorded ping sequence between PC (192.168.1.2) and MCB167-NET board (192.168.1.3)
    will be used and its content will be fed the upper level protocols.
    
    \warning this dataset has to be used in a mutual exclusive manner (only one dataset may be active at once)
 */
//#define DUMPDEV_USE_PING_DATA

/** If DUMPDEV_USE_HTTPGET_DATA is defined, a recored ping sequence between PC (192.168.1.2) and MCB167-NET board (192.168.1.3)
    will be used and its content will be fed the upper level protocols.
    
    \warning this dataset has to be used in a mutual exclusive manner (only one dataset may be active at once)
 */
#define DUMPDEV_USE_HTTPGET_DATA

/* NS: made some problems
#ifdef DUMPDEV_USE_PING_DATA && DUMPDEV_USE_HTTPGET_DATA
#error "Please use only one set of dumped packets! (combination of DUMPDEV_USE_PING_DATA and DUMPDEV_USE_HTTPGET_DATA is not tested)"
#endif
*/

#ifdef DUMPDEV_USE_PING_DATA
#include "testing/functional/ipsec-lwip-integration/dumpdev-pingdata.h"	/** include dumped packets */
#endif

#ifdef DUMPDEV_USE_HTTPGET_DATA
#include "testing/functional/ipsec-lwip-integration/dumpdev-httpgetdata.h"	/** include dumped packets */
#endif


unsigned char dumpdev_pingpacket[74] =	
{
    0x00, 0xE0, 0x29, 0x25, 0x60, 0x6C, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x3C, 0x07, 0xF5, 0x00, 0x00, 0x80, 0x01, 0xAF, 0x78, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8,
    0x01, 0x01, 0x08, 0x00, 0x40, 0x5C, 0x05, 0x00, 0x08, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
} ;  /**< sample ICMP Ping packet */


unsigned char dumpdev_ESP_packet[114] =
{
    0x00, 0xA0, 0x24, 0x15, 0x3E, 0x12, 0x00, 0xE0, 0x29, 0x25, 0x60, 0x6C, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x64, 0x79, 0x28, 0x00, 0x00, 0x40, 0x32, 0x7D, 0xC4, 0xC0, 0xA8, 0x01, 0x28, 0xC0, 0xA8,
    0x01, 0x03, 0x00, 0x00, 0x10, 0x06, 0x00, 0x00, 0x00, 0x01, 0xA7, 0x36, 0xBA, 0x27, 0x8D, 0x39,
    0xC5, 0x09, 0x49, 0x26, 0x53, 0x04, 0x07, 0xC9, 0x4D, 0xBB, 0x16, 0x59, 0x0E, 0x4E, 0x0B, 0x35,
    0xBD, 0x56, 0x0A, 0x84, 0x26, 0x8E, 0x24, 0x8D, 0xB7, 0xAE, 0x8C, 0x59, 0x3F, 0x0C, 0x40, 0x22,
    0x2B, 0x82, 0xA3, 0xC8, 0x3D, 0xDB, 0x0B, 0xA9, 0xD7, 0x81, 0x1A, 0x52, 0xC3, 0x26, 0xDB, 0x19,
    0xCB, 0xFF, 0x67, 0xA3, 0xA0, 0x04, 0x94, 0x8E, 0x36, 0xE4, 0xBF, 0xDF, 0x61, 0xBA, 0xCB, 0xB5,
    0xBA, 0xE9,
} ;		/**< sample ESP packet
         *
         * single ESP TCP SYN packet (FreeS/WAN configuration "manual6" used)
         * -------
         *
         * conn manual6
         *  authby=manual
         *  left=192.168.1.3
         *  leftid=@scuol
         *  right=192.168.1.40
         *  rightid=@stampa
         *  esp=3des
         *  spi=0x1006
         *  espenckey=0x01234567_01234567_01234567_01234567_01234567_0123456
         *
         */


/**
 * This helper function prints the payload of a pbuf packet buffer
 * @param  prefix  pointer to string (this text will be displayed at the beginning of each line)
 * @param  data    pointer to pbuf packet buffer data structure
 * @return void
 */
void ipsec_debug_dumppbufs(char *prefix, struct pbuf *data) 
{
	unsigned char *pbuf_pos_ptr = 0;
	unsigned char *tmp_ptr = 0;
    struct pbuf *q;
	int bytecount = 0;		// number of bytes which have already been dumped
	int i;

	if(data == NULL) {
		printf("%sCan't dump pbuf ==> data == NULL\n", prefix); 
		return;
	}

	printf("%sDumping pbuf (total length is %d bytes)\n", prefix, data->tot_len); 
	if(data->tot_len == 0) {
		printf(" => nothing to dump\n");
		return;
	}

    // q traverses through linked list of pbuf's
    // for(q = data; q != NULL; q = q->next)
	q = data;
	if((q != NULL) && (q->payload != NULL))
    {
		// dump all pbufs
     	pbuf_pos_ptr = (unsigned char *)q->payload;
		for(i = 0; i < q->len; i ++)
		{
			if((bytecount % 16) == 0) printf("%s%08Lx:", prefix, pbuf_pos_ptr);
			printf(" %02X", *pbuf_pos_ptr);
			if((bytecount % 16) == 15) printf("\n");
			pbuf_pos_ptr++;
			bytecount++;
		}
    }

	if((bytecount % 16) != 0) printf(" \n");
}


/**
 * This function must be called at regular intervals (i.g. 20 times per second).
 * It will allow the dump device driver to perform pending operations, such as
 * emptying the transmit buffer or feeding newly received data into the TCP/IP stack.
 *
 * @param  netif initialized lwIP network interface data structure of this device
 * @return void
 */
void dumpdev_service(struct netif *netif)
{
	dumpdev_input(netif);
}


/**
 * This function is used to transfer a received packet in newly allocated
 * pbuf-memory and pass it to upper protocol layers.
 *
 * Note: this is the place where the dumped packets are injected and passed 
 *       to higher protocol layers. It simulates the reception of a packet
 *       over the physical connection.
 *
 * @param  netif initialized lwIP network interface data structure of this device
 * @return void
 */
void dumpdev_input(struct netif *netif)
{
	struct dumpdev_stats *dumpdev_stats = netif->state;
	struct eth_hdr *ethhdr = NULL;
	struct pbuf *p = NULL, *q = NULL;
  	unsigned char *ptr = NULL;
  	unsigned char *input_ptr = NULL;
  	u16_t len = 0;
	u16_t i;

	IPSEC_LOG_MSG("dumpdev_input", ("*** start of dumpdev_input() ***") );

	/** @todo simulate reception of new packets HERE */

	/** If there is no INBOUND packet in the input queue, inject
	 *  a sample ESP packet to check the stacks behavior */
	len = sizeof(dumpdev_ESP_packet);
	input_ptr = dumpdev_ESP_packet;


#ifdef DUMPDEV_USE_HTTPGET_DATA
   	if(httpget_sequence[httpget_sequence_pos].packet_type == INBOUND)
	{
		len 		= httpget_sequence[httpget_sequence_pos].size;
		input_ptr	= httpget_sequence[httpget_sequence_pos].payload;
	}
	httpget_sequence_pos = (httpget_sequence_pos + 1) % HTTPGET_SEQUENCE_LENGTH;
#endif


#ifdef DUMPDEV_USE_PING_DATA
   	if(ping_sequence[ping_sequence_pos].packet_type == INBOUND)
	{
		len 		= ping_sequence[ping_sequence_pos].size;
		input_ptr	= ping_sequence[ping_sequence_pos].payload;
	}
	ping_sequence_pos = (ping_sequence_pos + 1) % PING_SEQUENCE_LENGTH;
#endif

	/* if there are some data ready, receive them and put them in a new pubf */
	if(len > 0)
    {
		/* allocate a pbuf memory of size 'len' */
      	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
		if(p != NULL)
		{
			/* copy payload */
			/** @todo replace this loop with memcpy() */
	        ptr = p->payload;
	        for (i = 0; i < p->len; i++)
			{
				ptr[i] = input_ptr[i];
			}
		}
		else {
			IPSEC_LOG_ERR("dumpdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, ("failed to allocate memory for incoming packet"));
		    return;
		}
	}
	else {
		IPSEC_LOG_DBG("dumpdev_input", IPSEC_STATUS_DATA_SIZE_ERROR, ("no data to read"));
		return;
	}

	if(p != NULL)
	{
		IPSEC_LOG_MSG("dumpdev_input", ("receiving data:") );
		ipsec_debug_dumppbufs("                                        INBOUND : ", p);
	}


	ethhdr = p->payload;		/* get MAC address (start of Ethernet frame) */

	switch(htons(ethhdr->type)) {
		case ETHTYPE_IP:		/* IP packet */
				q = etharp_ip_input(netif, p);	/* update ARP table */
				pbuf_header(p, -14);			/* remove Ethernet header */
				IPSEC_LOG_MSG("dumpdev_input", ("passing new packet higher layers") );
				netif->input(p, netif);			/* pass packet to higher network layers */
			break;
		case ETHTYPE_ARP:		/* ARP packet */
				/* pass p to ARP module, get ARP reply or ARP queued packet */
				q = etharp_arp_input(netif, (struct eth_addr *)&netif->hwaddr, p);
			break;
		default:				/* drop unknown packets */
				IPSEC_LOG_MSG("dumpdev_input", ("unknown packet -> drop") );
				pbuf_free(p);
				p = NULL;
				q = NULL;
			break;
	}

	/* send out the ARP reply or ARP queued packet */
	if (q != NULL)
	{
		/* q pbuf has been succesfully sent? */
		if (dumpdev_output(netif, q, -1) == IPSEC_STATUS_SUCCESS)	/** @todo ATTENTION: should be real IP, not -1 */
		{
			pbuf_free(q);
			q = NULL;
		}
		else {
			/* TODO re-queue packet in the ARP cache here (?) */
			pbuf_free(q);
			q = NULL;
		}
	}
	IPSEC_LOG_MSG("dumpdev_input", ("*** end of dumpdev_input() ***") );
}


/**
 * This function is used to send a packet out of the network device.
 *
 * Before dumping the frame (which is equivalent to sending data over the wire in
 * a real Ethernet driver), the MAC address must be resolved using the ARP module.
 * After the MAC address has been found, the packet will be "sent" (dumped).
 *
 * Note: this is the place where an automated check of outbound data can
 *       be added.
 *
 * @param  netif  initialized lwIP network interface data structure of this device
 * @param  p      pbuf containing a complete Ethernet frame as payload
 * @param  ipaddr destination address
 * @return err_t  status
 */
err_t dumpdev_output(struct netif *netif, struct pbuf *p, struct ip_addr *ipaddr)
{
	IPSEC_LOG_MSG("dumpdev_output", ("*** start of dumpdev_output() ***") );

	p = etharp_output(netif, ipaddr, p);

    /* network hardware address obtained? */
  	if (p != NULL)
  	{
		IPSEC_LOG_MSG("dumpdev_output", ("sending data:") );
		ipsec_debug_dumppbufs("                                        OUTBOUND: ", p);
		((struct dumpdev_stats *)netif->state)->sentbytes += p->tot_len;
	}
	IPSEC_LOG_MSG("dumpdev_output", ("*** end of dumpdev_output() ***") );
	return ERR_OK;
}


/**
 * This function simulates the low-level network interface
 *
 * Note: This function does currently nothing but return ERR_OK
 *
 * @param  netif  initialized lwIP network interface data structure of this device
 * @param  p      pbuf containing a complete Ethernet frame as payload
 * @return err_t  status
 */
err_t dumpdev_netlink_output(struct netif *netif, struct pbuf *p)
{
	void *dummy;			// dummy variable to avoid compiler warnings
	dummy = netif;
	dummy = (void*) p;
	IPSEC_LOG_MSG("dempdev_netlink_output()", ("simulate writing netlink stuff (not implemented, just returning ERR_OK)") );
	return ERR_OK;
}


/**
 * Initialize the dump network device
 *
 * This function must be called prior to any other operation with this device.
 * It sets the device name, MAC address, initializes statistics and performs
 * general configuration of the "dumpdev" device.
 *
 * @param  netif lwIP network interface data structure for this device. The structure must be
 *               initialized with IP, netmask and gateway address.
 * @return err_t return code
 */
err_t dumpdev_init(struct netif *netif)
{
	struct dumpdev_stats *dumpdev_stats;

	dumpdev_stats = mem_malloc(sizeof(struct dumpdev_stats));
	if (dumpdev_stats == NULL)
	{
		LWIP_DEBUGF(DUMPDEV_DEBUG, ("dumpdev_input: out of memory for dumpdev_stats\n"));
		return ERR_MEM;
	}

	/* set the name of this interface */
	netif->name[0] = DUMPDEV_NAME0;
	netif->name[1] = DUMPDEV_NAME1;

	/* use the same output function for all operations */
	netif->output = (void*)dumpdev_output;	/* usually called if the IP module wants to send data */
	netif->linkoutput = (void*)dumpdev_netlink_output; /* usually called if the ARP module wants to send data "as-is" */

	dumpdev_stats->sentbytes = 0;			/* reset statistic */
	netif->state = dumpdev_stats;			/* assign statistic */
  	netif->mtu = 1500;						/* set MTU */
	netif->flags = NETIF_FLAG_LINK_UP | NETIF_FLAG_BROADCAST;	/* device is always connected and supports broadcasts */
  	netif->hwaddr_len = 6;					/* set hardware address (MAC address) */
	netif->hwaddr[0] = 0x00;
	netif->hwaddr[1] = 0xe0;
	netif->hwaddr[2] = 0x29;
	netif->hwaddr[3] = 0x25;
	netif->hwaddr[4] = 0x60;
	netif->hwaddr[5] = 0x6c;

	return IPSEC_STATUS_SUCCESS;
}


