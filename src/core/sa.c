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

/** @file sa.c
 *  @brief This module contains the Security Association code
 *
 *  @author  Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 * Here we implement the Security Association concept from RFC 2401.
 * Both SPD and SAD are implemented.
 * At the time we do not support IKE and SA bundling. For having maximum flexibility 
 * two physically different tables (SPD and SAD) were implemented. They both provide 
 * functions to manipulate the database during run-time, so that a later IKE or SA-bundling
 * could be implemented.
 * The SPD contains the selector fields on which each IP packet needs to be
 * checked. After outbound packets found their SPD entry, they can access the SA via the
 * SA pointer.
 * Inbound packets can access their SA directly by applying the SPI to the SAD (by performing 
 * an SAD lookup).
 * Each IPsec enabled device needs to have its own set of SPD and SAD for each,
 * inbound and outbound processing. 
 *
 *  <B>IMPLEMENTATION:</B>
 * To be independent of any memory allocation we store the data from the tables in a 
 * statically allocated array. Because entries can be added and removed, a more flexible
 * method for creating the table is needed. The table itself is implemented with a doubly
 * linked list. 
 * The data is stored in the array records, but the sequence is determined by the linked-list
 * structure. 
 *
 * One database consists of two objects:
 * -# database structure: 		spd_table inbound_spd_table ;
 * -# array for storing data:	spd_entry inbound_spd_data[size] ;
 *
 * The 1st object holds the structure of the database (linked-list) while the second one is memory
 * for storing the objects.
 *
 *  <B>NOTES:</B>
 * To create and use a database you should guaranty the following sequence.
 * -# ipsec_spd_load_dbs(): to initialize the table
 * -# ipsec_spd_add(): to fill up as many records as the size (usually IPSEC_MAX_SA_ENTRIES) permits 
 * -# ipsec_spd_del(): to remove entries if required
 * -# ipsec_spd_lookup(): to check packets for a matching entry
 * -# ipsec_spd_release_dbs(): to clean up
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#include <string.h>

#include "ipsec/debug.h"
#include "ipsec/util.h"

#include "ipsec/sa.h"
#include "ipsec/ah.h"
#include "ipsec/esp.h"


/** 
 * This structure holds sets of databases used by one network interface. Each successful call of 
 * ipsec_spd_load_dbs() will return a pointer to an entry of this structure array. One entry holds
 * pointers to a inbound and outbound SPD and SAD table.  
 */
db_set_netif	db_sets[IPSEC_NR_NETIFS] ;

typedef struct ipsec_in_ip_struct /**< IPsec in IP structure - used to access headers inside SA */
{
	ipsec_ip_header 	 ip ;	/**< IPv4 header */
	union 
	{
		ipsec_ah_header  ah ;	/**< AH header  */
		ipsec_esp_header esp ;	/**< ESP header */
		ipsec_tcp_header tcp ;	/**< TCP header */
		ipsec_udp_header udp ;	/**< UDP header */
	} inner_header ;	
} ipsec_in_ip ;



/**
 * This function initializes the database set, allocated in a per-network manner.
 *
 * The data which is passed by the pointers should not be used by other functions except the 
 * ones of the SA-module. The data passed can be viewed as a place where the SA-module can store its
 * data (Security Policies or Security Associations). 
 * The tables which are passed to the function can already be filled up with static configuration
 * data. You can use the SPD_ENTRY and the SAD_ENTRY macro to do this in a nice way.
 *
 * Implementation
 * -# First the function gets a free entry (set of structs) out of the db_sets table.
 * -# Then it sets the pointer of this struct members.
 * -# On all entries in the table which are not already filled are set to IPSEC_FREE.
 * -# In the last and most ugly part of this function tables are linked together so that the linked
 * list is setup properly.
 *
 * @param inbound_spd_data 	pointer to a table where inbound Security Policies will be stored
 * @param outbound_spd_data pointer to a table where outbound Security Policies will be stored
 * @param inbound_sad_data 	pointer to a table where inbound Security Associations will be stored
 * @param outbound_sad_data pointer to a table where outbound Security Associations will be stored
 *
 * @return pointer to the initialized set of DB's if the setup was successful
 * @return NULL if loading failed
 */
db_set_netif	*ipsec_spd_load_dbs(spd_entry *inbound_spd_data, spd_entry *outbound_spd_data, sad_entry *inbound_sad_data, sad_entry *outbound_sad_data)
{
	int netif ;
	int index ;
	spd_entry 	*sp, *sp_next, *sp_prev ;
	sad_entry 	*sa, *sa_next, *sa_prev ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_spd_load_dbs", 
				  ("inbound_spd_data=%p, outbound_spd_data=%p, inbound_sad_data=%p, outbound_sad_data=%p",
			      (void *)inbound_spd_data, (void *)outbound_spd_data, (void *)inbound_sad_data, (void *)outbound_sad_data)
				 );
	
	/* get free entry */
	for(netif=0; netif < IPSEC_NR_NETIFS; netif++)
	{
		if(db_sets[netif].use_flag == IPSEC_FREE) break ;
	}
	if(netif >= IPSEC_NR_NETIFS)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_load_dbs", ("%p", (void *)NULL) );
		return NULL;
	}

	/* index points now the a free entry which is filled with the initialization data */
	db_sets[netif].inbound_spd.table = inbound_spd_data ;
	db_sets[netif].outbound_spd.table = outbound_spd_data ;
	db_sets[netif].inbound_sad.table = inbound_sad_data ;
	db_sets[netif].outbound_sad.table = outbound_sad_data ;

	db_sets[netif].use_flag = IPSEC_USED ;

	/* set none used entries from the tables to FREE */
	for(index=0; index < IPSEC_MAX_SPD_ENTRIES; index++)
		if(db_sets[netif].inbound_spd.table[index].use_flag != IPSEC_USED)
			db_sets[netif].inbound_spd.table[index].use_flag = IPSEC_FREE ;

	for(index=0; index < IPSEC_MAX_SPD_ENTRIES; index++)
		if(db_sets[netif].inbound_sad.table[index].use_flag != IPSEC_USED)
			db_sets[netif].inbound_sad.table[index].use_flag = IPSEC_FREE ;
	
	for(index=0; index < IPSEC_MAX_SAD_ENTRIES; index++)
		if(db_sets[netif].outbound_spd.table[index].use_flag != IPSEC_USED)
			db_sets[netif].outbound_spd.table[index].use_flag = IPSEC_FREE ;

	for(index=0; index < IPSEC_MAX_SAD_ENTRIES; index++)
		if(db_sets[netif].outbound_sad.table[index].use_flag != IPSEC_USED)
			db_sets[netif].outbound_sad.table[index].use_flag = IPSEC_FREE ;

	/* link the database entries together */

	/* inbound spd data */
	sp = inbound_spd_data ;
	/* if first entry is IPSEC_FREE, then there is nothing */
	if(sp->use_flag == IPSEC_USED)
	{
		db_sets[netif].inbound_spd.first = sp ;	
	
		if ((sp+1)->use_flag == IPSEC_USED)
		{
			sp_next = (sp+1) ;
		}
		else
		{
			sp_next = NULL ;
		}
	
		for(index=0, sp_prev=NULL;
	 		(index < IPSEC_MAX_SPD_ENTRIES) && (sp[index+1].use_flag == IPSEC_USED);
		    sp_prev = &sp[index], sp_next = &sp[index+2], index++)
			{
				sp[index].prev = sp_prev ;
				sp[index].next = sp_next ;
			}
	
			sp[index].next = NULL ;
			db_sets[netif].inbound_spd.last = &sp[index] ;	
	}
	else
	{
		/* there was no data */
		db_sets[netif].inbound_spd.first = NULL ;
		db_sets[netif].inbound_spd.last = NULL ;
	}

	/* outbound spd data */
	sp = outbound_spd_data ;
	/* if first entry is IPSEC_FREE, then there is nothing */
	if(sp->use_flag == IPSEC_USED)
	{
		db_sets[netif].outbound_spd.first = sp ;	
	
		if ((sp+1)->use_flag == IPSEC_USED)
		{
			sp_next = (sp+1) ;
		}
		else
		{
			sp_next = NULL ;
		}
	
		for(index=0, sp_prev=NULL;
	 		(index < IPSEC_MAX_SPD_ENTRIES) && (sp[index+1].use_flag == IPSEC_USED);
		    sp_prev = &sp[index], sp_next = &sp[index+2], index++)
			{
				sp[index].prev = sp_prev ;
				sp[index].next = sp_next ;
			}
	
			sp[index].next = NULL ;
			db_sets[netif].outbound_spd.last = &sp[index] ;	
	}
	else
	{
		/* there was no data */
		db_sets[netif].outbound_spd.first = NULL ;
		db_sets[netif].outbound_spd.last = NULL ;
	}


	/* inbound sad data */
	sa = inbound_sad_data ;
	/* if first entry is IPSEC_FREE, then there is nothing */
	if(sa->use_flag == IPSEC_USED)
	{
		db_sets[netif].inbound_sad.first = sa ;	
	
		if ((sa+1)->use_flag == IPSEC_USED)
		{
			sa_next = (sa+1) ;
		}
		else
		{
			sa_next = NULL ;
		}
	
		for(index=0, sa_prev=NULL;
	 		(index < IPSEC_MAX_SAD_ENTRIES) && (sa[index+1].use_flag == IPSEC_USED);
		    sa_prev = &sa[index], sa_next = &sa[index+2], index++)
			{
				sa[index].prev = sa_prev ;
				sa[index].next = sa_next ;
			}
	
			sa[index].next = NULL ;
			db_sets[netif].inbound_sad.last = &sa[index] ;	
	}
	else
	{
		/* there was no data */
		db_sets[netif].inbound_sad.first = NULL ;
		db_sets[netif].inbound_sad.last = NULL ;
	}

	/* outbound sad data */
	sa = outbound_sad_data ;
	/* if first entry is IPSEC_FREE, then there is nothing */
	if(sa->use_flag == IPSEC_USED)
	{
		db_sets[netif].outbound_sad.first = sa ;	
	
		if ((sa+1)->use_flag == IPSEC_USED)
		{
			sa_next = (sa+1) ;
		}
		else
		{
			sa_next = NULL ;
		}
	
		for(index=0, sa_prev=NULL;
	 		(index < IPSEC_MAX_SAD_ENTRIES) && (sa[index+1].use_flag == IPSEC_USED);
		    sa_prev = &sa[index], sa_next = &sa[index+2], index++)
			{
				sa[index].prev = sa_prev ;
				sa[index].next = sa_next ;
			}
	
			sa[index].next = NULL ;
			db_sets[netif].outbound_sad.last = &sa[index] ;	
	}
	else
	{
		/* there was no data */
		db_sets[netif].outbound_sad.first = NULL ;
		db_sets[netif].outbound_sad.last = NULL ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_load_dbs", ("&db_sets[netif] = %p", &db_sets[netif]) );
	return &db_sets[netif] ;
}

/**
 * This function is used to release the structure allocated in ipsec_spd_load_dbs().
 * The tables which were allocated in ipsec_spd_load_dbs() can now be freely used.
 *
 * @param dbs pointer to the set of databases got by ipsec_spd_load_dbs() which has to be released
 * @return IPSEC_STATUS_SUCCESS if release was successful
 * @return IPSEC_STATUS_FAILURE if release was not successful
 */
ipsec_status ipsec_spd_release_dbs(db_set_netif *dbs)
{
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_spd_release_dbs", 
				  ("dbs=%p",
			      (void *)dbs)
				 );

	dbs->inbound_spd.first = NULL ;
	dbs->inbound_spd.last = NULL ;
	dbs->inbound_spd.table = NULL ;

	dbs->outbound_spd.first = NULL ;
	dbs->outbound_spd.last = NULL ;
	dbs->outbound_spd.table = NULL ;

	dbs->inbound_sad.first = NULL ;
	dbs->inbound_sad.last = NULL ;
	dbs->inbound_sad.table = NULL ;

	dbs->outbound_sad.first = NULL ;
	dbs->outbound_sad.last = NULL ;
	dbs->outbound_sad.table = NULL ;

	dbs->use_flag = IPSEC_FREE ;

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_load_dbs", ("return = %d", IPSEC_STATUS_SUCCESS));
	return IPSEC_STATUS_SUCCESS ;
}

/**
 * Gives back a pointer to the next free entry from the given SPD table.
 *
 * @todo this function should probably be static
 * 
 * @param	table			pointer to the SPD table 
 * @return	pointer to the free entry if one was found
 * @return	NULL if no free entry was found
 */
spd_entry *ipsec_spd_get_free(spd_table *table)
{
	int index ;
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_spd_get_free", 
				  ("table=%p",
			      (void *)table)
				 );

	/* find first free entry */
	for(index = 0; index < IPSEC_MAX_SPD_ENTRIES; index++)
	{
		if (table->table[index].use_flag == IPSEC_FREE)
			break ;
	}
	/* if no free entry */
	if (index >= IPSEC_MAX_SPD_ENTRIES)
	{
		return NULL ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_get_free", ("&table->table[index] = %p", &table->table[index]));
	return &table->table[index] ;
}

/**
 * Adds a Security Policy to an SPD table.
 *
 * The SPD entries are added to a statically allocated array of SPD structs. The size
 * is defined by IPSEC_MAX_SPD_ENRIES, so there cannot be added more entries added as this
 * constant. 
 * The order of the entries within the table is not the same as the order within the array. 
 * The "table functionality" is implemented in a linked-list, so one must follow the links of 
 * the structure to get to the next entry.
 *
 * Implementation
 * -# This function first gets an empty entry out of the table passed by ipsec_spd_load_dbs().
 * -# If a free place was found, then the function arguments are copied to the appropriate place. 
 * -# Then the linked-list is re-linked.
 *
 * @param src		IP source address
 * @param src_net	Netmask for the source address
 * @param dst		IP destination address
 * @param dst_net	Netmask for the destination address
 * @param proto		Transport protocol 
 * @param src_port	Source Port
 * @param dst_port	Destination Port
 * @param policy	The policy defining how the packet matching the entry must be processed
 * @param table		Pointer to the SPD table
 * @return A pointer to the added entry when adding was successful
 * @return NULL when the entry could not have been added (no free entry or duplicate) 
 * @todo right now there is no special order implemented, maybe this is needed
 */
spd_entry *ipsec_spd_add(__u32 src, __u32 src_net, __u32 dst, __u32 dst_net, __u8 proto, __u16 src_port, __u16 dst_port, __u8 policy, spd_table *table)
{
	spd_entry 	*free_entry ;
	spd_entry	*tmp_entry ;
	int			table_size ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
              "ipsec_spd_add", 
			  ("src=%lu, src_net=%lu, dst=%lu, dst_net=%lu, proto=%u, src_port=%u, dst_port=%u, policy=%u, table=%p",
		      src, src_net, dst, dst_net, proto, src_port, dst_port, policy, (void *)table)
			 );

	table_size = table->size ;

	free_entry = ipsec_spd_get_free(table) ;
	if (free_entry == NULL) 
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_add", ("%p", (void *)NULL) );
		return NULL ;
	}

	/* add the fields to the entry */
	free_entry->src = src ;
	free_entry->src_netaddr = src_net ;
	free_entry->dest = dst ;
	free_entry->dest_netaddr = dst_net ;

	free_entry->protocol = proto ;
	free_entry->src_port = src_port ;
	free_entry->dest_port = dst_port ;
	free_entry->policy = policy ;

	free_entry->use_flag = IPSEC_USED ;

	/* re-link entry */
	/** @todo this part needs to be rewritten when an order is introduced */
	
	/* if added first entry in array */
	if(table->first == NULL)
	{
		table->first = free_entry ;
		table->first->next = NULL ;
		table->first->prev = NULL ;
		table->last = free_entry ;
	}
	else
	{
		/* go till end of list */
		for(tmp_entry = table->first; tmp_entry->next != NULL; tmp_entry = tmp_entry->next)
		{
		}

		/* inset at end */
		free_entry->prev = tmp_entry ;
		tmp_entry->next = free_entry ;
		free_entry->next = NULL ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_add", ("free_entry=%p", (void *)free_entry) );
	return free_entry ;
}
/**
 * Adds a Security Association to a Security Police.
 *
 * @param entry 	pointer to the SPD entry where the SA should be added
 * @param sa		a pointer to the SA which is added to the SPD
 * @return IPSEC_STATUS_SUCCESS the entry was added successfully
 */
ipsec_status ipsec_spd_add_sa(spd_entry *entry, sad_entry *sa)
{
	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
              "ipsec_spd_add_sa", 
			  ("entry=%p, sa=%p",
		      (void *)entry, (void *)sa)
			 );

	entry->sa = sa ;

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_add_sa", ("return = %d", IPSEC_STATUS_SUCCESS) );
	return IPSEC_STATUS_SUCCESS ;
}

/**
 * Deletes an Security Policy from an SPD table.
 *
 * This function is simple. If the pointer is within the range of the table, then
 * the entry is cleared. If the pointer does not match, nothing happens.
 *
 * @param entry Pointer to the SPD entry which needs to be deleted
 * @param table Pointer to the SPD table
 *
 * @return IPSEC_STATUS_SUCCESS	entry was deleted properly
 * @return IPSEC_STATUS_FAILURE entry could not be deleted because not found, or invalid pointer
 * @todo right now there is no special order implemented, maybe this is needed
 */
ipsec_status ipsec_spd_del(spd_entry *entry, spd_table *table)
{
	spd_entry		*next_ptr ;
	spd_entry		*prev_ptr ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
              "ipsec_spd_del", 
			  ("entry=%p, table=%p",
		      (void *)entry, (void *)table)
			 );

	/* check range */		
	if((entry >= table->table ) && (entry <= (table->table + (IPSEC_MAX_SPD_ENTRIES*sizeof(spd_entry)))))
	{
		/* first clear associated SA if there is one */
		/**@todo probably the SA should also be deleted */

		/* relink table */
	
		if(entry->use_flag != IPSEC_USED)
		{
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_del", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE ;
		}

		/* relink previous with next */
		prev_ptr = entry->prev ;
		next_ptr = entry->next ;
		if(prev_ptr)
			prev_ptr->next = next_ptr ;
		if(next_ptr)
			next_ptr->prev = prev_ptr ;

		/* if removed last entry */
		if(entry->next == NULL)
		{
			table->last == entry->prev ;
		}

		/* if removed first entry */
		if(entry == table->first)
		{
			table->first = entry->next ;
		}

		/* clear field */
		entry->use_flag = IPSEC_FREE ;

		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_del", ("return = %d", IPSEC_STATUS_SUCCESS) );
		return IPSEC_STATUS_SUCCESS ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_del", ("return = %d", IPSEC_STATUS_FAILURE) );
	return IPSEC_STATUS_FAILURE ;
}

/**
 * Returns an pointer to an SPD entry which matches the packet.
 *
 * Inbound packets must be checked against the inbound SPD and outbound
 * packets must be checked against the outbound SPD.
 *
 * Implementation
 *
 * This function checks all the selector fields of the SPD table. The port numbers
 * are only checked if the protocol is TCP or UDP.
 * An entry which has a value of 0 is the same as the '*' which means everything.
 * 
 * @param	header	Pointer to an IP packet which is checked
 * @param 	table	Pointer to the SPD inbound/outbound table
 * @return 	Pointer to the matching SPD entry
 * @return 	NULL if no entry matched 
 * @todo port checking should be implemnted also
 */
spd_entry *ipsec_spd_lookup(ipsec_ip_header *header, spd_table *table)
{
	spd_entry	*tmp_entry ;
	ipsec_in_ip	*ip ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
              "ipsec_spd_lookup", 
			  ("header=%p, table=%p",
		      (void *)header, (void *)table)
			 );

	ip = (ipsec_in_ip*) header ;

	/* compare and return when all fields match */
	for(tmp_entry = table->first; tmp_entry != NULL; tmp_entry = tmp_entry->next)
	{
		if(ipsec_ip_addr_maskcmp(header->src, tmp_entry->src, tmp_entry->src_netaddr))
		{
			if(ipsec_ip_addr_maskcmp(header->dest, tmp_entry->dest, tmp_entry->dest_netaddr))
			{
				if((tmp_entry->protocol == 0) || tmp_entry->protocol == header->protocol)
				{
					if(header->protocol == IPSEC_PROTO_TCP)
					{
						if((tmp_entry->src_port == 0) || (tmp_entry->src_port == ip->inner_header.tcp.src)) 
							if( (tmp_entry->dest_port == 0) || (tmp_entry->dest_port == ip->inner_header.tcp.dest)) 
							{
								IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", ("tmp_entry = %p", (void *) tmp_entry) );
								return tmp_entry ;
							}
					}
					else if(header->protocol == IPSEC_PROTO_UDP)
					{
							if((tmp_entry->src_port == 0) || (tmp_entry->src_port == ip->inner_header.udp.src)) 
								if( (tmp_entry->dest_port == 0) || (tmp_entry->dest_port == ip->inner_header.udp.dest)) 
								{
									IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", ("tmp_entry = %p", (void *) tmp_entry) );
									return tmp_entry ;
								}
					} 
					else
					{
						IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", ("tmp_entry = %p", (void *) tmp_entry) );
						return tmp_entry ;
					}
				}
			}
		}
	}
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_spd_lookup", ("return = %p", (void *) NULL) );
	return NULL ;
}

/**
 * Prints a single SPD entry.
 *
 * @param entry pointer to the SPD entry
 * @return void
 */
void ipsec_spd_print_single(spd_entry *entry)
{
	char 		log_message[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		ip_addr1[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		ip_addr2[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		ip_addr3[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		ip_addr4[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char		protocol[10+1] ;
	char		policy[10+1] ;

	strcpy(ip_addr1, ipsec_inet_ntoa(entry->src)) ;
	strcpy(ip_addr2, ipsec_inet_ntoa(entry->src_netaddr)) ;
	strcpy(ip_addr3, ipsec_inet_ntoa(entry->dest)) ;
	strcpy(ip_addr4, ipsec_inet_ntoa(entry->dest_netaddr)) ;

	switch(entry->protocol)
	{
		case IPSEC_PROTO_TCP:
			strcpy(protocol, " TCP") ;
			break ;
		case IPSEC_PROTO_UDP:
			strcpy(protocol, " UDP") ;
			break ;
		case IPSEC_PROTO_AH:
			strcpy(protocol, "  AH") ;
			break ;
		case IPSEC_PROTO_ESP:
			strcpy(protocol, " ESP") ;
			break ;
		case IPSEC_PROTO_ICMP:
			strcpy(protocol, "ICMP") ;
			break ;
		default :
			sprintf(protocol, "%4d", entry->protocol) ;
	}

	switch(entry->policy)
	{
		case POLICY_APPLY:
			strcpy(policy, "  APPLY") ; 
			break ;
		case POLICY_BYPASS:
			strcpy(policy, " BYPASS") ; 
			break ;
		case POLICY_DISCARD:
			strcpy(policy, "DISCARD") ; 
			break ;
		default:
			strcpy(policy, "UNKNOWN") ;
	}

	sprintf(log_message, 	"%15s/%15s   %15s/%15s %3s %5u %5u    %7s  0x%p",
       						ip_addr1, ip_addr2, ip_addr3, ip_addr4,
							protocol,
							ipsec_ntohs(entry->src_port),
							ipsec_ntohs(entry->dest_port),
							policy,
							entry->sa) ;

	printf("    %s\n", log_message) ;

	return ;
}

/**
 * Prints a Security Policy Database.
 *
 * @param table pointer to the SPD table
 * @return void
 */
void ipsec_spd_print(spd_table *table)
{
	spd_entry 	*tmp_ptr ;

	IPSEC_LOG_MSG("ipsec_spd_print", ("Printf Security Policy Database")) ;
	printf("      src-addr/net-addr               dst-addr/net-addr                proto prt:src/dest  policy  SA\n") ;

	if(table->first == NULL)
	{
		printf("      SPD table is empty\n") ;
	}

	/* loop over all entries and print them */
	for(tmp_ptr = table->first; tmp_ptr != NULL; tmp_ptr = tmp_ptr->next)
	{
		ipsec_spd_print_single(tmp_ptr) ;
	}

	return ;
}

/**
 * Gives back a pointer to the next free entry from the given SA table.
 *
 * @todo this function should probably be static
 * 
 * @param	table			pointer to the SA table 
 * @return	pointer to the free entry if one was found
 * @return	NULL if no free entry was found
 */
sad_entry *ipsec_sad_get_free(sad_table *table)
{
	int index ;

	/* find first free entry */
	for(index = 0; index < IPSEC_MAX_SAD_ENTRIES; index++)
	{
		if (table->table[index].use_flag == IPSEC_FREE)
			break ;
	}
	/* if no free entry */
	if (index >= IPSEC_MAX_SAD_ENTRIES)
	{
		return NULL ;
	}

	return &table->table[index] ;
}

/**
 * Adds an Security Association to an SA table.
 *
 * The SA entries are added to a statically allocated array of SAD structs. The size
 * is defined by IPSEC_MAX_SAD_ENTRIES, so there cannot be added more entries added as this
 * constant. 
 * The order of the entries within the table is not the same as the order within the array. 
 * The "table functionality" is implemented in a linked-list, so one must follow the links of 
 * the structure to get to the next entry.
 *
 * Implementation
 * -# This function first gets an empty entry out of the table passed by ipsec_spd_load_dbs().
 * -# If a free place was found, then the function arguments are copied to the appropriate place. 
 * -# Then the linked-list is re-linked.
 *
 * @param entry		pointer to the SA structure which will be copied into the table
 * @param table		pointer to the table where the SA is added
 * @return A pointer to the added entry when adding was successful
 * @return NULL when the entry could not have been added (no free entry or duplicate) 
 * @todo right now there is no special order implemented, maybe this is needed
 */
sad_entry *ipsec_sad_add(sad_entry *entry, sad_table *table) 
{
	sad_entry 	*free_entry ;
	sad_entry	*tmp_entry ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_sad_add", 
				  ("entry=%p, table=%p",
			      (void *)entry, (void *)table )
				 );
	free_entry = ipsec_sad_get_free(table) ;
	if (free_entry == NULL) 
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_add", ("return = %p", (void *) NULL) );
		return NULL ;
	}

	/* copy the fields */
	free_entry->dest = entry->dest ;
	free_entry->dest_netaddr = entry->dest_netaddr ;
	free_entry->spi = entry->spi ;
	free_entry->protocol = entry->protocol ;
	free_entry->mode = entry->mode ;
	free_entry->sequence_number = entry->sequence_number ;
	free_entry->replay_win = entry->replay_win ;
	free_entry->lifetime = entry->lifetime ;
	free_entry->path_mtu = entry->path_mtu ;
	free_entry->enc_alg = entry->enc_alg ;
	memcpy(free_entry->enckey, entry->enckey, IPSEC_MAX_ENCKEY_LEN) ;
	free_entry->auth_alg = entry->auth_alg ;
	memcpy(free_entry->authkey, entry->authkey, IPSEC_MAX_AUTHKEY_LEN) ;

	free_entry->use_flag = IPSEC_USED ;

	/* re-link entry */
	/** @todo this part needs to be rewritten when an order is introduced */
	
	/* if added first entry in array */
	if(table->first == NULL)
	{
		table->first = free_entry ;
		table->first->next = NULL ;
		table->first->prev = NULL ;
		table->last = free_entry ;
	}
	else
	{
		/* go till end of list */
		for(tmp_entry = table->first; tmp_entry->next != NULL; tmp_entry = tmp_entry->next)
		{
		}
		/* inset at end */
		free_entry->prev = tmp_entry ;
		tmp_entry->next = free_entry ;
		free_entry->next = NULL ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_add", ("free_entry = %p", (void *) free_entry) );
	return free_entry ;
}

/**
 * Deletes an Security Association from an SA table.
 *
 * This function is simple. If the pointer is within the range of the table, then
 * the entry is cleared. If the pointer does not match, nothing happens.
 *
 * @param entry Pointer to the SA entry which needs to be deleted
 * @param table Pointer to the SA table
 *
 * @return IPSEC_STATUS_SUCCESS	entry was deleted properly
 * @return IPSEC_STATUS_FAILURE entry could not be deleted because not found, or invalid pointer
 * @todo right now there is no special order implemented, maybe this is needed
 */
ipsec_status ipsec_sad_del(sad_entry *entry, sad_table *table) 
{
	sad_entry		*next_ptr ;
	sad_entry		*prev_ptr ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_sad_del", 
				  ("entry=%p, table=%p",
			      (void *)entry, (void *)table )
				 );

	/* check range */		
	if((entry >= table->table ) && (entry <= (table->table + (IPSEC_MAX_SAD_ENTRIES*sizeof(sad_entry)))))
	{
		/* relink table */
	
		if(entry->use_flag != IPSEC_USED)
		{
			IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_del", ("return = %d", IPSEC_STATUS_FAILURE) );
			return IPSEC_STATUS_FAILURE ;
		}

		/* relink previous with next */
		prev_ptr = entry->prev ;
		next_ptr = entry->next ;
		if(prev_ptr)
			prev_ptr->next = next_ptr ;
		if(next_ptr)
			next_ptr->prev = prev_ptr ;

		/* if removed last entry */
		if(entry->next == NULL)
		{
			table->last == entry->prev ;
		}

		/* if removed first entry */
		if(entry == table->first)
		{
			table->first = entry->next ;
		}

		/* clear field */
		entry->use_flag = IPSEC_FREE ;


		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_del", ("return = %d", IPSEC_STATUS_SUCCESS) );
		return IPSEC_STATUS_SUCCESS ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_del", ("return = %d", IPSEC_STATUS_FAILURE) );
	return IPSEC_STATUS_FAILURE ;
}

/**
 * Gives back a pointer to a SA matching the SA selectors.
 *
 * For incoming packets the IPsec packet must be checked against the inbound SAD and
 * for outgoing packets the packet must be checked against the outbound SAD.
 *
 * Implementation
 * It simply loops over all entries and returns the first match.
 *
 * @param dest	destination IP address
 * @param proto	IPsec protocol
 * @param spi	Security Parameters Index
 * @param table	pointer to the SAD table
 * @return pointer to the SA entry if one matched
 * @return NULL if no matching entry was found
 */
sad_entry *ipsec_sad_lookup(__u32 dest, __u8 proto, __u32 spi, sad_table *table)
{
	sad_entry	*tmp_entry ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_sad_lookup", 
				  ("dest=%lu, proto=%d, spi=%lu, table=%p",
			      dest, proto, spi, (void *)table ) 
				 );

	/* compare and return when all fields match */
	for(tmp_entry = table->first; tmp_entry != NULL; tmp_entry = tmp_entry->next)
	{
		if(ipsec_ip_addr_maskcmp(dest, tmp_entry->dest, tmp_entry->dest_netaddr))
		{
			if(tmp_entry->protocol == proto)
			{
				if(tmp_entry->spi == spi)
				{
					IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_lookup", ("tmp_entry = %p", (void *)tmp_entry) );
					return tmp_entry ;
				}
			}
		}
	}
	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_lookup", ("return = %p", (void *)NULL) );
	return NULL ;
}

/**
 * Prints a single SA entry.
 *
 * @param entry pointer to the SA entry which will be printed
 * @return void
 */
void ipsec_sad_print_single(sad_entry *entry)
{
	char 		log_message[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		dest[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		dest_netaddr[IPSEC_LOG_MESSAGE_SIZE+1] ;
	char 		crypto[10+1] ;

	strcpy(dest, ipsec_inet_ntoa(entry->dest)) ;
	strcpy(dest_netaddr, ipsec_inet_ntoa(entry->dest_netaddr)) ;

	if (entry->protocol == IPSEC_PROTO_AH)
		strcpy(crypto, entry->auth_alg == IPSEC_HMAC_MD5 ? " MD5" : "SHA1") ;
	else
		strcpy(crypto, entry->enc_alg == IPSEC_DES ? " DES" : "3DES") ;

	sprintf(log_message, 	"%15s/%15s %4s %5s  %4s   %10lu %5d %10lu %4d %8x 0x%p ",
       						dest, 
							dest_netaddr,
							entry->protocol == IPSEC_PROTO_ESP ? "ESP" : " AH", 
							entry->mode == IPSEC_TUNNEL ? "  TUN" : "TRANS", 
							crypto,
							entry->sequence_number,
							entry->replay_win,
							entry->lifetime,
							entry->path_mtu,
							ipsec_ntohl(entry->spi),
							entry
							) ;
	printf("     %s\n", log_message) ;

	return ;
}

/**
 * Prints a  SAD table.
 *
 * @param table pointer to the SAD table which will be printed
 * @return void
 */
void ipsec_sad_print(sad_table *table)
{
	sad_entry 	*tmp_ptr ;

	IPSEC_LOG_MSG("ipsec_sad_print", ("Print Security Association Database")) ;
	printf("     dest/dest netaddr                proto mode crypto seq          win   ltime    mtu      spi  addr\n") ;

	if(table->first == NULL)
	{
		printf("      SAD table is empty\n") ;
	}

	/* loop over all entries and print them */
	for(tmp_ptr = table->first; tmp_ptr != NULL; tmp_ptr = tmp_ptr->next)
	{
		ipsec_sad_print_single(tmp_ptr) ;
	}
}

/**
 * Returns the SPI from an IPsec header out of an IP packet.
 *
 * @param header	pointer to the IP header having an IPsec header as payload
 * @return the SPI if one could be extracted
 * @return 0 if no SPI could be extracted (not IPsec packet)
 */
__u32 ipsec_sad_get_spi(ipsec_ip_header *header)
{
	ipsec_in_ip	*ptr ;

	IPSEC_LOG_TRC(IPSEC_TRACE_ENTER, 
	              "ipsec_sad_get_spi", 
				  ("header=%p",
			      (void *)header)
				 );


	ptr = (ipsec_in_ip*)header ;

	if (ptr->ip.protocol == IPSEC_PROTO_ESP)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", ("ptr->inner_header.esp.spi = %ul", ptr->inner_header.esp.spi) );
		return ptr->inner_header.esp.spi ;
	}

 	if (ptr->ip.protocol == IPSEC_PROTO_AH)
	{
		IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", ("ptr->inner_header.ah.spi = %ul", ptr->inner_header.ah.spi) );
		return ptr->inner_header.ah.spi ;
	}

	IPSEC_LOG_TRC(IPSEC_TRACE_RETURN, "ipsec_sad_get_spi", ("return = 0") );
	return 0 ;
}

/**
 * Flushes an SPD table and sets a new default entry. The default entry allows to keep 
 * a door open for IKE.
 *
 * @param table			pointer to the SPD table
 * @param def_entry 	pointer to the default entry
 * @return IPSEC_STATUS_SUCCESS if the flush was successful
 * @return IPSEC_STATUS_FAILURE if the flush failed
 */
ipsec_status ipsec_spd_flush(spd_table *table, spd_entry *def_entry)
{
	memset(table->table, 0, sizeof(spd_entry)*IPSEC_MAX_SPD_ENTRIES) ;
	table->first = NULL ;
	table->first = NULL ;

	if(ipsec_spd_add(	def_entry->src,
						def_entry->src_netaddr,
						def_entry->dest,
						def_entry->dest_netaddr,
						def_entry->protocol,
						def_entry->src_port,
						def_entry->dest_port,
						def_entry->policy,
						table) == NULL)
		return IPSEC_STATUS_FAILURE ;

	return IPSEC_STATUS_SUCCESS ;
}

/**
 * Flushes an SAD table.
 *
 * @param table	pointer to the SAD table
 * @return IPSEC_STATUS_SUCCESS if the flush was successful
 */
ipsec_status ipsec_sad_flush(sad_table *table)
{
	memset(table->table, 0, sizeof(spd_entry)*IPSEC_MAX_SAD_ENTRIES) ;
	table->first = NULL ;
	table->first = NULL ;
	
	return IPSEC_STATUS_SUCCESS ;
}
