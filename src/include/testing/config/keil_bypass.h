/** @file keil_bypass.h
 *  @brief Test configuration: connection between any host and MCB167NET board (192.168.1.4) - IPsec is disabled (BYPASS for all packets)
 */

/**************************/
/* inbound configurations */
/**************************/

/* SAD configuartion data */
sad_entry inbound_sad_config[IPSEC_MAX_SAD_ENTRIES] = {
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY

};

/* SPD configuration data */
spd_entry inbound_spd_config[IPSEC_MAX_SAD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
	SPD_ENTRY(  192,168,1,0,     255,255,255,0,   192,168,1,3,     255,255,255,255,   0, 0,   0, POLICY_BYPASS, 0),
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
	EMPTY_SPD_ENTRY
};


/***************************/
/* outbound configurations */
/***************************/

/* SAD configuartion data */
sad_entry outbound_sad_config[IPSEC_MAX_SAD_ENTRIES] = {
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,			  
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY
};

/* SPD configuration data */
spd_entry outbound_spd_config[IPSEC_MAX_SPD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
	SPD_ENTRY(  192,168,1,3,     255,255,255,255, 192,168,1,0,     255,255,255,0,   0, 0,   0,   POLICY_BYPASS,   0),
 	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
	EMPTY_SPD_ENTRY
};

