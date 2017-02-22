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

/** @file debug.h
 *  @brief Collection of common debug routines and macros
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch>
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#ifndef __IPSEC_DEBUG_H__
#define __IPSEC_DEBUG_H__

#include <stdio.h>
#include "ipsec/util.h"

/*! \brief If IPSEC_ERROR is defined, severe configuration errors and <br>
 *         not manageable states such as running out of memory are logged. <br>
 *         It is recommended to have this feature enabled by default. */
#define IPSEC_ERROR			/**< turns on error logging */

/*! \brief If less critical errors should also be logged, this feature must 
           be enabled. The produced additional output can be a supplement 
           to the error messages logged under IPSEC_ERROR. */
//#define IPSEC_DEBUG			/**< turns on debug messages */

/*! \brief This feature controls informative messages. They are particularly helpful 
           to have a "lightweight trace" of the program execution. */
#define IPSEC_MESSAGE		/**< turns on informative message logging */

/*! \brief If in-depth information with details of all passed and returned 
           parameters is needed, IPSEC_TRACE must be defined. Since this feature 
           produces a vast amount of information, it is recommended to disable it by default. */
//#define IPSEC_TRACE			/**< turns on trace messages for ipsec testing */

/*! \brief If defined, auditable events according to the IPsec RFC's are logged. */
#define IPSEC_AUDIT			/**< turns on audit messages according RFC 2401 */

/*! \brief This feature is only used inside the test routines and prints log messages in an uniform style.  */
#define IPSEC_TEST			/**< turns on test messages for ipsec testing */

/*! \brief Printing a HEX-dump of large memory buffers can be very time consuming. Only if defined, dumping of buffers is enabled. */
//#define IPSEC_DUMP_BUFFERS	/**< turns on dumping of large memory buffers (disable to speed-up) */

/*! \brief Some information is printed in tables. To avoid this time consuming operation, this feature must be disabled. */
#define IPSEC_TABLES		/**< turns on logging for any kind of tables */



/*! \brief This macro defines a standard log message size, which can be used for concatenation of log messages (sprintf(), etc) */
#define IPSEC_LOG_MESSAGE_SIZE (128)


/* @def When error logging is activated (IPSEC_ERROR), then we define a logging function for it. Otherwise nothing is printed */
#ifdef IPSEC_ERROR
	#define IPSEC_LOG_ERR(__function_name__, __code__, __message__) { \
				printf("ERR %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define IPSEC_LOG_ERR(__function_name__, __code__, __message__)
#endif


/* @def When debug messages are turned on (IPSEC_DEBUG), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef IPSEC_DEBUG
	#define IPSEC_LOG_DBG(__function_name__, __code__, __message__) { \
				printf("DBG %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define IPSEC_LOG_DBG(__function_name__, __code__, __message__)
#endif

/* @def When informative messages are turned on (IPSEC_MESSAGE), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef IPSEC_MESSAGE
	#define IPSEC_LOG_MSG(__function_name__, __message__) { \
				printf("MSG %-28s: ", __function_name__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define IPSEC_LOG_MSG(__function_name__, __message__)
#endif

/* @def When informative audit messages are turned on (IPSEC_AUDIT), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef IPSEC_AUDIT
	#define IPSEC_LOG_AUD(__function_name__, __code__, __message__) { \
				printf("AUD %-28s: %9d : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
#else
	#define IPSEC_LOG_AUD(__function_name__, __code__, __message__)
#endif

/* @def When test messages are turned on (IPSEC_TEST), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef IPSEC_TEST
	#define IPSEC_LOG_TST(__function_name__, __code__, __message__) { \
				printf("TST %-28s: %9s : ", __function_name__, __code__); \
				printf __message__ ;  \
				printf("\n"); \
			}
	#define IPSEC_LOG_TST_NOMSG(__function_name__, __code__) printf("TST %-28s: %9s : ", __function_name__, __code__)
#else
	#define IPSEC_LOG_TST(__function_name__, __code__, __message__)
	#define IPSEC_LOG_TST_NOMSG(__function_name__, __code__)
#endif


/* @def When trace messages are turned on (IPSEC_TRACE), then we define a logging function for it. Otherwise nothing is printed. */
#ifdef IPSEC_TRACE
	#define IPSEC_TRACE_ENTER   1
	#define IPSEC_TRACE_RETURN -1

	extern int __ipsec_trace_indication;		/* variable used inside debug macros */
	extern int __ipsec_trace_indication__pos;	/* variable used inside debug macros */

	/* the useless (__ipsec_trace_indication < 0) test is only here to avoid compiler warnings */
	#define IPSEC_LOG_TRC(__action__, __function_name__, __message__) { \
				if(__action__ == IPSEC_TRACE_ENTER | (__ipsec_trace_indication < 0)) { \
					__ipsec_trace_indication++; \
	                for(__ipsec_trace_indication__pos = 0; __ipsec_trace_indication__pos < __ipsec_trace_indication; __ipsec_trace_indication__pos++) {\
						printf("  "); \
					} \
					printf("ENTER  %s(", __function_name__); \
				} else { \
	                for(__ipsec_trace_indication__pos = 0; __ipsec_trace_indication__pos < __ipsec_trace_indication; __ipsec_trace_indication__pos++) {\
						printf("  "); \
					} \
					__ipsec_trace_indication--; \
					printf("RETURN %s(", __function_name__); \
				} \
				printf __message__ ;\
				printf(")\n"); \
			}
	#define IPSEC_LOG_TST_NOMSG(__function_name__, __code__) printf("TST %-28s: %9s : ", __function_name__, __code__)
#else
	#define IPSEC_LOG_TRC(__action__, __function_name__, __message__)
#endif

/* @def When buffer dumping is turned on (IPSEC_DUMP_BUFFERS), then we define a dump function for it. Otherwise nothing is printed. */
#ifdef IPSEC_DUMP_BUFFERS
	#define IPSEC_DUMP_BUFFER(__prefix__, __buffer__, __offset__, __length__) ipsec_dump_buffer(__prefix__, __buffer__, __offset__, __length__)
#else
	#define IPSEC_DUMP_BUFFER(__prefix__, __buffer__, __offset__, __length__)
#endif

#endif