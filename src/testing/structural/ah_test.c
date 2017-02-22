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

/** @file ah_test.c
 *  @brief Test functions for IP Authentication Header (AH)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> 
 *
 *  <B>OUTLINE:</B>
 *
 *  This file contains test functions used to verify the AH code.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/ah.h"
#include "ipsec/sa.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"

#include "testing/structural/ah_test-sample_ah_packet.h"

/**
 * Test the ICV- and header-check of an AH-protected packet
 * @return int number of tests failed in this function
 */
int ah_test_ipsec_ah_check(void) 
{
	sad_entry packet1_sa =	{ 	SAD_ENTRY(	192,168,1,40, 255,255,255,255, 
								0x1010, 
								IPSEC_PROTO_AH, IPSEC_TUNNEL, 
								IPSEC_3DES, 
								0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 
								IPSEC_HMAC_MD5,  
								0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0)
							};
	int local_error_count	= 0;
	int payload_size 		= 0;
	int payload_offset		= 0;
	int ret_val;

	// feed valid AH packet
	ret_val = ipsec_ah_check((ipsec_ip_header *)&ah_test_sample_ah_outer_packet, (int *)&payload_offset, (int *)&payload_size, (sad_entry *)&packet1_sa);
	if(ret_val != IPSEC_STATUS_SUCCESS) {
		local_error_count++;
		IPSEC_LOG_TST("ah_test_ipsec_ah_check", "FAILURE", ("ipsec_ah_check(ah_test_sample_ah_packet) failed")) ;
	}

	// feed invalid packet (offset + 1)
	ret_val = ipsec_ah_check(((ipsec_ip_header *)&ah_test_sample_ah_outer_packet[1]), (int *)&payload_offset, (int *)&payload_size, (sad_entry *)&packet1_sa);
	if(ret_val == IPSEC_STATUS_SUCCESS) {
		local_error_count++;
		IPSEC_LOG_TST("ah_test_ipsec_ah_check", "FAILURE", ("ipsec_ah_check(invalid_packet) was not rejected")) ;
	}

	return local_error_count;
}

/**
 * Tests encapsulating an IP packet into an AH header
 * @return int number of tests failed in this function
 */
int ah_test_ipsec_ah_encapsulate(void) 
{
	sad_entry packet1_sa =	{ 	SAD_ENTRY(	192,168,1,5, 255,255,255,255, 
								0x1016, 
								IPSEC_PROTO_AH, IPSEC_TUNNEL, 
								IPSEC_3DES, 
								0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 
								IPSEC_HMAC_MD5,  
								0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0)
							};

	static unsigned char encapsulated_ah_packet[104] =
	{
	    0x45, 0x00, 0x00, 0x68, 0xE8, 0x03, 0x00, 0x00, 0x40, 0x33, 0x0F, 0x07, 0xC0, 0xA8, 0x01, 0x03, 
	    0xC0, 0xA8, 0x01, 0x05, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x16, 0x00, 0x00, 0x00, 0x01, 

		// ICV
		0x6F, 0x1D, 0x8E, 0x94, 0x4F, 0x70, 0x23, 0xE8, 0x53, 0xB1, 0x51, 0xBF,
		
		0x45, 0x00, 0x00, 0x3C, 
	    0xE7, 0x7A, 0x40, 0x00, 0x40, 0x06, 0xCF, 0xC5, 0xC0, 0xA8, 0x01, 0x28, 0xC0, 0xA8, 0x01, 0x03, 
	    0x80, 0x1A, 0x00, 0x50, 0x84, 0xB9, 0xC5, 0x66, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, 0x7E, 0xB8, 
	    0x1F, 0x75, 0x00, 0x00, 0x02, 0x04, 0x3F, 0x5C, 0x04, 0x02, 0x08, 0x0A, 0x00, 0x0F, 0x22, 0x1C, 
	    0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x00, 
	} ;

	int local_error_count 	= 0;
	int payload_size 		= 0;
	int payload_offset		= 0;
	__u32 src;
	__u32 dst;
	int ret_val = 0;
	unsigned char buffer[sizeof (ah_test_sample_ah_inner_packet) + 100];

	local_error_count = 0;

	src = 0x0301A8C0;
	dst = 0x0501A8C0;

	/* copy packet in a buffer where space for the new headers is left */
	memcpy(buffer + 100, ah_test_sample_ah_inner_packet, sizeof(ah_test_sample_ah_inner_packet));

	ret_val = ipsec_ah_encapsulate((ipsec_ip_header *)(buffer + 100), 
	                                      (int *)&payload_offset, (int *)&payload_size, 
										  (sad_entry *)&packet1_sa,
										  src, dst
										 );
	if(ret_val != 0) {
		local_error_count++;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("ipsec_ah_encapsulate() failed (rev_val indicates no SUCCESS)")) ;
	} 

	if(payload_offset != -44)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("offset was not calculated properly")) ;
	}

	if(payload_size != 104)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("length was not calculated properly")) ;
	}

	payload_offset = -44;
	payload_size = 104;

	if(memcmp(((char*)(buffer + 100)) + payload_offset, encapsulated_ah_packet, payload_size) != 0)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("packet was not properly encapsulated"));
	}

	return local_error_count;
}

/**
 * Main test function for the AH tests.
 * It does nothing but calling the subtests one after the other.
 */
void ah_test(test_result *global_results)
{
	test_result 	sub_results	= {
						  6, 			
						  2,			
						  0, 			
						  0, 			
					};

	int retcode;

	retcode = ah_test_ipsec_ah_check();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ah_test_ipsec_ah_check()", (""));

	retcode = ah_test_ipsec_ah_encapsulate();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ah_test_ipsec_ah_encapsulate()", (""));

	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}



