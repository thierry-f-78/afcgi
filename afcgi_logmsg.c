/*
 * Copyright (c) 2009 Thierry FOURNIER
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License.
 *
 */

#include "afcgi.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#ifdef AFCGI_USE_SYSLOG
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#endif

// for displaying fate
const char *mois[12] = {
	"Jan",  
	"Feb",  
	"Mar",  
	"Apr",  
	"May",  
	"Jun",  
	"Jul",  
	"Aug",  
	"Sep",  
	"Oct",  
	"Nov",  
	"Dec"   
};

#define HOSTNAME_LEN 50

static uint32_t  afcgi_log_flags = 0;
static int       afcgi_log_level = LOG_WARNING;
static char      afcgi_hostname[HOSTNAME_LEN];
static int       afcgi_hostname_len;
static char     *afcgi_application_name;
static int       afcgi_application_name_len;
#ifdef AFCGI_USE_SYSLOG
static int       afcgi_facility;
static int       afcgi_syslog_socket;
static struct sockaddr_in afcgi_syslog_addr;
#endif

void afcgi_set_log_opt(uint32_t flags, ...){
	int code_ret;
	va_list ap;
	char *str;
	int port;

	afcgi_log_flags |= flags;
	va_start(ap, flags);

	// init options display hostname
	if((flags & AFCGI_LOG_DSP_HOSTNAME) != 0){
		gethostname(afcgi_hostname, HOSTNAME_LEN);
		if (afcgi_hostname[0] == '\0')
			strncpy(afcgi_hostname, "localhost", HOSTNAME_LEN);
		afcgi_hostname[HOSTNAME_LEN-1] = '\0';
		afcgi_hostname_len = strlen(afcgi_hostname);
	}

	// init option log level
	if((flags & AFCGI_LOG_DSP_LOG_LEVEL) != 0){
		afcgi_log_level = va_arg(ap, int);
		if(afcgi_log_level < LOG_EMERG ||
		   afcgi_log_level > LOG_DEBUG){
			afcgi_logmsg(LOG_ERR, "log level %d not avalaible",
			             afcgi_log_level);
			exit(1);
		}
	}

	// init option display application name
	if((flags & AFCGI_LOG_DSP_APP_NAME) != 0){
		str = va_arg(ap, char *);
		afcgi_application_name     = strdup(str);
		afcgi_application_name_len = strlen(afcgi_application_name);
	}

	// init option syslog
	#ifdef AFCGI_USE_SYSLOG
	if((flags & AFCGI_LOG_SYSLOG) != 0){

		/* get facility */
		afcgi_facility = va_arg(ap, int);

		/* get ip */
		str = va_arg(ap, char *);

		/* get port */
		port = va_arg(ap, int);

		afcgi_syslog_addr.sin_family = AF_INET;
		afcgi_syslog_addr.sin_port = htons(port);
		code_ret = inet_pton(AF_INET, str, &afcgi_syslog_addr.sin_addr.s_addr);
		if (code_ret <= 0)
			afcgi_logmsg(LOG_ERR, "%s is not a valid address family", str);

		/* open socket */
		afcgi_syslog_socket = socket(PF_INET, SOCK_DGRAM, 0);
	}
	#endif

	va_end(ap);
}

#define AFCGI_LOG_MSG_BUF 4096
#define AFCGI_MAX_INFO_LEN 56
void __afcgi_logmsg(int priority, const char *file, const char *function,
                    int line, char *fmt, ...) {
	va_list ap;
	char buffer[AFCGI_LOG_MSG_BUF];
	char *str_msg;
	char *str_current;
	char *str_disp;
	int syslog_hdrlen;
	time_t current_t;
	struct tm *tm;
	int len;
	int tmp_len;
	int clen;
	int display_two_points;
	uint32_t switch_flags;
	char *p;

	// check if I do log this priority
	if(priority > afcgi_log_level){
		return;
	}

	str_disp = buffer;
	str_current = buffer;
	clen = 0;
	display_two_points = 0;

#ifdef AFCGI_USE_SYSLOG
	/* build syslog header */
	if((afcgi_log_flags & AFCGI_LOG_SYSLOG) != 0){
		syslog_hdrlen = snprintf(str_current, AFCGI_LOG_MSG_BUF - clen,
		                         "<%d>", afcgi_facility + priority);
		clen += syslog_hdrlen;
		str_current += syslog_hdrlen;
	}
#endif

	// generate time tag
	if((afcgi_log_flags & AFCGI_LOG_DSP_TIME) != 0){
		current_t = time(NULL);
		tm = localtime(&current_t);
		len = snprintf(str_current, AFCGI_LOG_MSG_BUF - clen,
		               "%s % 2d %02d:%02d:%02d",
		               mois[tm->tm_mon],
		               tm->tm_mday,
		               tm->tm_hour,
		               tm->tm_min,
		               tm->tm_sec);

		// next position
		str_current += len;
		clen += len;
		display_two_points = 1;
	}

	// generate host name
	if ((afcgi_log_flags & AFCGI_LOG_DSP_HOSTNAME) != 0) {
		if (display_two_points && 1 < (AFCGI_LOG_MSG_BUF - clen)) {
			str_current[0] = ' ';
			str_current++;
			clen++;
		}
		if (afcgi_hostname_len < AFCGI_LOG_MSG_BUF - clen) {
			memcpy(str_current, afcgi_hostname,
			                    afcgi_hostname_len);
			str_current += afcgi_hostname_len;
			clen += afcgi_hostname_len;
			display_two_points = 1;
		}
	}

	// generate appli name
	if ((afcgi_log_flags & AFCGI_LOG_DSP_APP_NAME) != 0) {
		if (display_two_points && 1 < (AFCGI_LOG_MSG_BUF - clen)) {
			str_current[0] = ' ';
			str_current++;
			clen++;
		}
		if (afcgi_application_name_len <
		    AFCGI_LOG_MSG_BUF - clen) {
			memcpy(str_current, afcgi_application_name,
			                    afcgi_application_name_len);
			str_current += afcgi_application_name_len ;
			clen += afcgi_application_name_len;
			display_two_points = 1;
		}
	}

	// generate pid
	if((afcgi_log_flags & AFCGI_LOG_DSP_PID) != 0){
		len = snprintf(str_current, AFCGI_LOG_MSG_BUF - clen,
		               "[%d]", getpid());
		str_current += len;
		clen += len;
		display_two_points = 1;
	}

	// syslog info separation
	if(display_two_points == 1){
		if(2 < (AFCGI_LOG_MSG_BUF - clen)){
			str_current[0] = ':';
			str_current[1] = ' ';
			str_current += 2;
			clen += 2;
		}
	}

	// generate header
	switch_flags = ( afcgi_log_flags & 
	               ( AFCGI_LOG_DSP_FILE | AFCGI_LOG_DSP_FUNCTION | 
	                 AFCGI_LOG_DSP_LINE ));
	len = 0;
	switch(switch_flags){
		case AFCGI_LOG_DSP_FILE:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s", file);
			break;
		case AFCGI_LOG_DSP_FUNCTION:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s", function);
			break;
		case AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%d", line);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_FUNCTION:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s %s", function, file);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s:%d", file, line);
			break;
		case AFCGI_LOG_DSP_FUNCTION|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s %d", function, line);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_FUNCTION|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, AFCGI_MAX_INFO_LEN, "[%s %s:%d",
			               function, file, line);
			break;
	}
	if (len > AFCGI_MAX_INFO_LEN) {
		str_current += AFCGI_MAX_INFO_LEN - 1;
		clen += AFCGI_MAX_INFO_LEN - 1;
	} else {
		str_current += len;
		clen += len;
	}
	str_current[0] = ']';
	str_current[1] = ' ';
	str_current += 2;
	clen += 2;
	
	// generate message
	str_msg = str_current;
	tmp_len = AFCGI_LOG_MSG_BUF - clen;
	va_start(ap, fmt);
	len = vsnprintf(str_current, tmp_len, fmt, ap);
	va_end(ap);
	if (len > tmp_len)
		clen += tmp_len - 1;
	else
		clen += len;

	/* check for unprintable characters */
	for (p = str_current; *p != 0; p++)
		if (!isprint(*p))
			*p = '.';

	/* set line feed */
	*p = '\n';

	// out on system standard error
	if ((afcgi_log_flags & AFCGI_LOG_STDERR) != 0)
		write(2, buffer + syslog_hdrlen, clen + 1 - syslog_hdrlen);

	// out on syslog
	#ifdef AFCGI_USE_SYSLOG
	if((afcgi_log_flags & AFCGI_LOG_SYSLOG) != 0){
		sendto(afcgi_syslog_socket, buffer, clen + 1, MSG_DONTWAIT | MSG_NOSIGNAL,
		       (struct sockaddr *)&afcgi_syslog_addr, sizeof(afcgi_syslog_addr));
	}
	#endif
}
