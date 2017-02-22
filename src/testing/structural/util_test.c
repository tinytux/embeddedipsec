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

/** @file util_test.c
 *  @brief Test functions for the util module.
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  This file contains all the test functions used to test the util module.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/debug.h"
#include "ipsec/ipsec.h"
#include "testing/structural/structural_test.h"

/**
 * Test all debug log macros
 */
int test_ipsec_inet_addr(void)
{
	int 			local_error_count = 0 ;
	unsigned long	ipsec_inet_address ;

	ipsec_inet_address = ipsec_inet_addr("192.168.100.100") ;
	if(ipsec_inet_address != 0x6464A8C0)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("192.168.100.100 was not properly converted to network order")) ;
	}

	ipsec_inet_address = ipsec_inet_addr("255.255.255.255") ;
	if(ipsec_inet_address != 0xFFFFFFFF)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("255.255.255.255 was not properly converted to network order")) ;
	}


	ipsec_inet_address = ipsec_inet_addr("255.0.0.0") ;
	if(ipsec_inet_address != 0x000000FF)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("255.255.0.0 was not properly converted to network order")) ;
	}


	ipsec_inet_address = ipsec_inet_addr("192.168.1.2") ;
	if(ipsec_inet_address != 0x0201A8C0)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("192.168.1.2 was not properly converted to network order")) ;
	}


	ipsec_inet_address = ipsec_inet_addr("1.2.3.4") ;
	if(ipsec_inet_address != 0x04030201)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("1.2.3.4 was not properly converted to network order")) ;
	}


	ipsec_inet_address = ipsec_inet_addr("1.2.3.100") ;
	if(ipsec_inet_address != 0x64030201)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("test_ipsec_inet_addr", "FAILURE", ("1.2.3.100 was not properly converted to network order")) ;
	}	

	return local_error_count ;
}



/**
 * Testfunciton for ipsec_update_replay_window
 * @return int number of tests failed in this function
 */
int util_test_ipsec_update_replay_window() 
{
	int local_error_count = 0;
	int i, errors;
	__u32 bitmap;   			/* saved session state to detect replays - must be 32 bits. */
	__u32 lastSeq;        		/* saved session state to detect replays */
	__u32 test_sequence;



	/* Test 1: sequence number is increasing strictly from 1 to 101 */
	/* Expected result: checks and updates should pass error free   */
	bitmap 			= 0;
	lastSeq 		= 0;
	test_sequence 	= 1;
	errors 			= 0;
	
	for(i = 0; i < 100; i++) 
	{
		/* check window */	   
		if(ipsec_check_replay_window(test_sequence, lastSeq, bitmap) != IPSEC_AUDIT_SUCCESS)
		{
//			IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
			errors++;
		}

		/* update window */
		if(ipsec_update_replay_window(test_sequence, (__u32 *)&lastSeq, (__u32 *)&bitmap) != IPSEC_AUDIT_SUCCESS)
		{
//			IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
			errors++;
		}

		/* update sequence */
		test_sequence++;
	}
	
	if(errors != 0)
	{
		local_error_count++ ;
		IPSEC_LOG_TST(util_test_ipsec_update_replay_window, "FAILURE", ("%d errors when sequence number is increasing strictly - this should be error free!", errors)) ;
	}
	  


	/* Test 2: replay detection - sequence counting from 0..100, then repeating 90..95 */
	/* Expected result: 6 packets should fail  */
	bitmap 			= 0xFFFFFFFF;
	lastSeq 		= 0x00000064;
	test_sequence 	= 0x00000065;
	errors 			= 0;

 	// Simulate Replay of packet 90 to 95
	test_sequence = 90;
	for(i = 0; i < 6; i++) 
	{
		/* check window */	   
		if(ipsec_check_replay_window(test_sequence, lastSeq, bitmap) != IPSEC_AUDIT_SUCCESS)
		{
//			IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
			errors++;
		}

		/* update window */
		if(ipsec_update_replay_window(test_sequence, (__u32 *)&lastSeq, (__u32 *)&bitmap) != IPSEC_AUDIT_SUCCESS)
		{
//			IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
			errors++;
		}

		/* update sequence */
		test_sequence++;
	}
	
	if(errors != 12)
	{
		local_error_count++ ;
		IPSEC_LOG_TST(util_test_ipsec_update_replay_window, "FAILURE", ("Replay check did not work - %d errors detected (expected: 12 errors)", errors)) ;
	}
	  


	/* Test 3: out of window tests */
	/* Expected result: sequence numbers outside the window should be rejected */
	bitmap 			= 0xFFFFFFFF;
	lastSeq 		= IPSEC_SEQ_MAX_WINDOW * 5 - 1;
	test_sequence 	= IPSEC_SEQ_MAX_WINDOW * 5;
	errors 			= 0;


	// Test packet with too low  sequence number
	test_sequence 	= IPSEC_SEQ_MAX_WINDOW * 2;
	
	/* check window */	   
	if(ipsec_check_replay_window(test_sequence, lastSeq, bitmap) != IPSEC_AUDIT_SUCCESS)
	{
//		IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
		errors++;
	}
	/* update window */
	if(ipsec_update_replay_window(test_sequence, (__u32 *)&lastSeq, (__u32 *)&bitmap) != IPSEC_AUDIT_SUCCESS)
	{
//		IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
		errors++;
	}

	// Test packet with too high sequence number
	test_sequence 	= IPSEC_SEQ_MAX_WINDOW * 8;
	
	/* check window */	   
	if(ipsec_check_replay_window(test_sequence, lastSeq, bitmap) != IPSEC_AUDIT_SUCCESS)
	{
//		IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay check (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
		errors++;
	}
	/* update window */
	if(ipsec_update_replay_window(test_sequence, (__u32 *)&lastSeq, (__u32 *)&bitmap) != IPSEC_AUDIT_SUCCESS)
	{
//		IPSEC_LOG_TST("util_test_ipsec_update_replay_window", "FAILURE", ("packet rejected by anti-replay update (lastSeq=%08lx, seq=%08lx, window size=%d)", lastSeq, test_sequence, IPSEC_SEQ_MAX_WINDOW) );
		errors++;
	}
	
	if(errors != 3)
	{
		local_error_count++ ;
		IPSEC_LOG_TST(util_test_ipsec_update_replay_window, "FAILURE", ("Out-of-window tests failed.")) ;
	}



	return local_error_count;
}

/**
 * Test function for all the log functions
 * (Note: some of these tests are commented out by default to make the log output more uniform)
 */
void util_debug_test(test_result *global_results)
{
	test_result 	sub_results	= {
						  9,
						  2,			
						  0, 		
						  0, 	
					};

	int retcode;

	/*
	IPSEC_LOG_DBG("ipsec_esp_encapsulate", 0, "EN") ;

	IPSEC_LOG_ERR("ipsec_esp_encapsulate", -5, "was not able to encapsulate the ESP packet because of invalid packet header") ;
	IPSEC_LOG_ERR("ipsec_md5_check", -5000, "failled due to bad function pointer") ;

	IPSEC_LOG_MSG("ipsec_esp_encapsulate", "the cause of the previous error may be a bug in the HW device driver") ;

	IPSEC_LOG_AUD("ipsec_esp_decapsulate", -1050, "datagram could not be decapsulated because it is not valid") ;

	IPSEC_LOG_DBG("ipsec_esp_encapsulate", 0, "EX") ;	

	IPSEC_LOG_TST("test_debug", 0, "if the above printed messages appear nicely, then it works fine!") ;
	*/

	IPSEC_LOG_TST("test_debug", "NOTE", ("These text printing macros have no particular test"));

	retcode = test_ipsec_inet_addr() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "test_util_ipsec_inet_addr()", (" "));

	retcode = util_test_ipsec_update_replay_window();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "util_test_ipsec_update_replay_window()", (" "));


	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}





