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

/** @file md5_test.c
 *  @brief This module contains all the test functions used to test MD5
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 * The purpose of this module is to provide structural tests for the MD5 functions.
 * The tests we did here are not how they should be. Because we took over the code 
 * from another project (OpenSSL) which is widely used and tested we assume that they 
 * work basically (yes I know assumptions are the worst mistakes of programmers).
 *
 *  <B>IMPLEMENTATION:</B>
 *  We call the four basic functions used to implement a HMAC and let them do their job.
 *  After the function is called we compare the result with the expected output.
 *
 *  Whenever a test fails we print out the INPUT, OUTPUT and the EXPECTED OUTPUT.
 *
 *  <B>NOTES:</B>
 *  This test do NOT fully prove the correctness of this code.
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/md5.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"


/**
 * Testfunciton for MD5_Init
 * @return int number of tests failed in this function
 */
int md5_test_MD5_Init(void)
{
	MD5_CTX orig = { 0x67452301L, 0xefcdab89L, 0x98badcfeL, 0x10325476L, 0, 0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0} ;
	MD5_CTX input, test;

	memset(&input, 0, sizeof(MD5_CTX)) ;
	memcpy(&test, &input, sizeof(MD5_CTX)) ;

	MD5_Init(&test) ;

	if(memcmp(&test, &orig, sizeof(MD5_CTX)) != 0)
	{
		IPSEC_LOG_TST("md5_test_init", "FAILURE", ("MD5_Init() failed")) ;
		printf("     INPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&input, 0, sizeof(MD5_CTX));
		printf("     OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&test, 0, sizeof(MD5_CTX));
		printf("     EXPECTED OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&orig, 0, sizeof(MD5_CTX));

		return 1;
	}

	return 0 ;
}

/**
 * Testfunciton for MD5_Update
 * @return int number of tests failed in this function
 */
int md5_test_MD5_Update()
{
	MD5_CTX orig = { 	0xCB6180E8L, 0x2FA83EA8L, 0x43278D6CL, 0xB9526934,
						0x000002E0, 0x0, 
						0x74616877, 0x206F6420, 0x77206179, 0x20746E61, 0x20726F66, 0x68746F6E, 0x3F676E69,      
						0, 0, 0, 0, 0, 0, 0, 0, 0,
						0x001C          
					} ;
	MD5_CTX test, input ;

	unsigned char k_ipad[65];
    unsigned char k_opad[65];


	char text[] = "what do ya want for nothing?" ;
	int text_len = 28 ;

	char key[] = "Jefe" ;
	int key_len = 4 ;

	int i ;

	memset(k_ipad, '\0', sizeof(k_ipad));  
	memset(k_opad, '\0', sizeof(k_opad));  
	memcpy(k_ipad, key, key_len); 		   
	memcpy(k_opad, key, key_len); 

	for (i=0; i<64; i++) 
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	memset(&input, 0, sizeof(MD5_CTX)) ;

	MD5_Init(&input);      
    
   	memcpy(&test, &input, sizeof(MD5_CTX)) ; 

	MD5_Update(&test, k_ipad, 64);  
	MD5_Update(&test, text, text_len);

	if(memcmp(&test, &orig, sizeof(MD5_CTX)) != 0)
	{
		IPSEC_LOG_TST("md5_test_update", "FAILURE", ("MD5_Update() failed")) ;
		printf("     INPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&input, 0, sizeof(MD5_CTX));
		printf("     OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&test, 0, sizeof(MD5_CTX));
		printf("     EXPECTED OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&orig, 0, sizeof(MD5_CTX));

		return 1;
	}

	return 0 ;
}

/**
 * Testfunciton for MD5_Final
 * @return int number of tests failed in this function
 */
int md5_test_MD5_Final()
{
	MD5_CTX input ;

	unsigned char k_ipad[65];   
    unsigned char k_opad[65];    

	char text[] = "what do ya want for nothing?" ;
	int text_len = 28 ;

	char key[] = "Jefe" ;
	int key_len = 4 ;

	#define DIGEST_SIZE (16)
	unsigned char orig_digest[] = { 0xC3, 0xDB, 0x14, 0xC0, 0x65, 0xF5, 0x52, 0x03, 0xB0, 0x33, 0xC8, 0x1A, 0x69, 0x7B, 0x97, 0xC5 } ;
	char test_digest[DIGEST_SIZE+1] ;

	int i ;

	memset(k_ipad, '\0', sizeof(k_ipad));  
	memset(k_opad, '\0', sizeof(k_opad));  
	memcpy(k_ipad, key, key_len); 		   
	memcpy(k_opad, key, key_len); 

	for (i=0; i<64; i++) 
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	memset(&input, 0, sizeof(MD5_CTX)) ;

	MD5_Init(&input);      
    
	MD5_Update(&input, k_ipad, 64);  
	MD5_Update(&input, text, text_len);

	MD5_Final(test_digest, &input);

	if(memcmp(&test_digest, &orig_digest, DIGEST_SIZE) != 0)
	{
		IPSEC_LOG_TST("md5_test_final", "FAILURE", ("MD5_Final() failed")) ;
		printf("     INPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&input, 0, sizeof(MD5_CTX));
		printf("     OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&test_digest, 0, DIGEST_SIZE);
		printf("     EXPECTED OUTPUT:\n") ;
		IPSEC_DUMP_BUFFER("          ", (char*)&orig_digest, 0, DIGEST_SIZE);

		return 1 ;
	}

	return 0 ;
}

/**
 * Main testfunction for the MD5 tests.
 * It does nothing but calling the subtests one after the other.
 */
void md5_test(test_result *global_results)
{
	test_result 	sub_results	= {
						  3, 		
						  3,		
						  0, 		
						  0, 		
					};

	int retcode;

	retcode = md5_test_MD5_Init();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "md5_test_MD5_Init()", ("ported from openssl.org"));

	retcode = md5_test_MD5_Update();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "md5_test_MD5_Update()", ("ported from openssl.org"));

	retcode = md5_test_MD5_Final();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "md5_test_MD5_Final()", ("ported from openssl.org"));


	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}



