/** @file phy_2001_ah_sha1.h
 *  @brief Test configuration: AH SHA1 connection between FreeS/WAN host (192.168.1.5) and PhyCORE167-HS/E board (192.168.1.4)
 */

/**************************/
/* inbound configurations */
/**************************/

/* SAD configuartion data */
sad_entry inbound_sad_config[IPSEC_MAX_SAD_ENTRIES] = {
	SAD_ENTRY(	192,168,1,4, 255,255,255,255, 
				0x2001, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				IPSEC_HMAC_SHA1, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67
			  ),
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY,
	  EMPTY_SAD_ENTRY
};

/* SPD configuration data */
spd_entry inbound_spd_config[IPSEC_MAX_SAD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
	SPD_ENTRY(  192,168,1,5,     255,255,255,255, 192,168,1,4,     255,255,255,255, 0, 				0,     0,     POLICY_APPLY,   &inbound_sad_config[0]),
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
	SAD_ENTRY(	192,168,1,5, 255,255,255,255, 
				0x2001, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				IPSEC_HMAC_SHA1, 
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67
		  ),
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY,			  
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY
};

/* SPD configuration data */
spd_entry outbound_spd_config[IPSEC_MAX_SPD_ENTRIES] = {
/*            source                            destination                       protocol          ports         policy          SA pointer 
 *            address          network          address          network                            src    dest                              */
	SPD_ENTRY(  192,168,1,4,     255,255,255,255, 192,168,1,5,     255,255,255,255, 0, 				0,     0,     POLICY_APPLY,   &outbound_sad_config[0]),
 	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
   	EMPTY_SPD_ENTRY,
	EMPTY_SPD_ENTRY
};

