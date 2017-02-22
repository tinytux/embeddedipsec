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

/** @file structural_test.h
 *  @brief Header file of the structural test main program
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#ifndef __STRUCTURAL_TEST_H__
#define __STRUCTURAL_TEST_H__

typedef struct test_result_struct
{
	unsigned int tests; 			/**< number of tests performed in all local function */
	unsigned int functions;			/**< number of local functions to test */
	unsigned int errors; 			/**< local error counter */
	unsigned int notimplemented;	/**< local counter of not implemented functions */
} test_result;

/** 
 * \brief This macro is used in all test functions to update statistics and print status
 * information.
 * @todo this doxygen tag is not working. probably because of the complexity of the macro
 */
#define IPSEC_TESTING_EVALUATE(__retcode__, __sub_results__, __functionname__, __msg__)   { \	
			switch(__retcode__) { \
				case IPSEC_STATUS_SUCCESS: ; \
						IPSEC_LOG_TST_NOMSG(__functionname__, "SUCCESS  "); \
						printf __msg__ ;  \
						printf("\n"); \
						break; \
				case IPSEC_STATUS_NOT_IMPLEMENTED: ; __sub_results__.notimplemented++; \
						IPSEC_LOG_TST_NOMSG(__functionname__, "NOT IMPL."); \
						printf __msg__ ;  \
						printf("\n"); \
						break; \
				default: ; __sub_results__.errors += __retcode__; \
						IPSEC_LOG_TST_NOMSG(__functionname__, "ERROR    "); \
						printf("(%d errors)", __retcode__); \
						printf __msg__ ;  \
						printf("\n"); \
			} \
		} \




#endif


