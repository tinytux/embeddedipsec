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

/** @file main.c
 *  @brief Main file of structural tests
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  This module contains the main function where the structural test is executed. It basically loops 
 *  over the test routines which are provided by the tested modules. Each module which needs to be tested 
 *  must provide a function with the following interface: void (*function)(test_result *). Before a test for an 
 *  appropriate module is performed, the function needs to be registred in the test_function_set array.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  The implementation uses an array of function pointers. The programmer needs to register the new test 
 *  function statically in the main file of this module. During execution of the test, all functions registered
 *  in the test_function_set are executed.
 *
 *  <B>NOTES:</B>
 *
 *  to add a test to this testing procedure you have to perform the following steps:
 *  -# declare the new test function as extern 
 *  -# add the test function and its name to the test_function_set
 *  -# recompile and be assure that the tests return 'successful' or with 'not implemented'
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#include "testing/structural/structural_test.h"
#include "ipsec/debug.h"
#include "ipsec/util.h"

extern void serinit(void) ;

/* declare all test functions here */
extern void util_debug_test(test_result *);
extern void des_test(test_result *);
extern void md5_test(test_result *);
extern void sha1_test(test_result *);
extern void sa_test(test_result *) ;
extern void ah_test(test_result *) ;
extern void esp_test(test_result *) ;

typedef struct test_set_struct
{
	void (*function)(test_result *);	/**< function pointer to the test function*/
	char *name ;						/**< name of the test function */
} test_set;

test_set test_function_set[] = 
{
			{ util_debug_test, 	"util_debug_test"	},
			{ des_test, 		"des_test"			},
			{ md5_test, 		"md5_test"			}, 
			{ sha1_test,		"sha1_test"			},
			{ sa_test, 			"sa_test"			},
			{ ah_test, 			"ah_test"			},
			{ esp_test,			"esp_test"			}
} ;

#define NR_OF_TESTFUNCTIONS sizeof(test_function_set)/sizeof(test_set) /**< defines the number of test functions */


/**
 * Executes the structural testing framework.
 *
 * @return void
 */
void main(void)
{
	int 			i ;
	float			percents;

	test_result 	global_results	= {0, 0, 0, 0};
	
#ifdef SIMULATOR
  	serinit();
#endif


	IPSEC_LOG_MSG("main", (" ")) ;
	IPSEC_LOG_MSG("main", ("structural testing started")) ;
	IPSEC_LOG_MSG("main", ("compiled on %s at %s", __DATE__, __TIME__)) ;
	IPSEC_LOG_MSG("main", ("CVS ID: $Id: main.c,v 1.11 2003/12/11 22:02:11 schec2 Exp $\n")) ;

	/* loop and execute all test functions */
  	for (i = 0; i < NR_OF_TESTFUNCTIONS; i++)
	{
		test_function_set[i].function((test_result *)&global_results);
		printf("\n");
	}

	printf("\n");
	IPSEC_LOG_MSG("main", ("structural testing finished:")) ;

	percents = 100.00;
	if(global_results.tests > 0) {
		percents = 100.00*(1.00-((float)global_results.errors/(float)global_results.tests));
	}
	IPSEC_LOG_MSG("main", (" o %6.2f%% correct  (%d of %d tests passed)", percents, (global_results.tests-global_results.errors), global_results.tests));

	percents = 100.00;
	if(global_results.functions > 0) {
		percents = 100.00*(1.00-((float)global_results.notimplemented/(float)global_results.functions));
	}
	IPSEC_LOG_MSG("main", (" o %6.2f%% complete (%d of %d functions implemented)", percents, (global_results.functions-global_results.notimplemented), global_results.functions));
	
	while(1) ;

  return ;
}


