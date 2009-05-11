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
#include <sys/utsname.h>

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

static uint32_t  afcgi_log_flags = 0;
static int       afcgi_log_level = LOG_WARNING;
static char     *afcgi_hostname;
static int       afcgi_hostname_len;
static char     *afcgi_application_name;
static int       afcgi_application_name_len;

void afcgi_set_log_opt(uint32_t flags, ...){
	struct utsname utsinfo;
	int code_ret;
	va_list ap;
	char *str;

	afcgi_log_flags |= flags;
	va_start(ap, flags);

	// init options display hostname
	if((flags & AFCGI_LOG_DSP_HOSTNAME) != 0){
		code_ret = uname(&utsinfo);
		if(code_ret == -1){
			afcgi_logmsg(LOG_ERR, "uname[%d]: %s",
			             errno, strerror(errno));
			exit(1);
		}
		afcgi_hostname = strdup(utsinfo.sysname);
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
		options = LOG_NDELAY;
		str = va_arg(ap, char *);
		ident = strdup(str);
		facility = va_arg(ap, int);
		if(facility == 1){
			options |= LOG_PID;
		}
		facility = va_arg(ap, int);
		openlog(ident, options, facility);
	}
	#endif

	va_end(ap);
}

#define AFCGI_LOG_MSG_BUF 4096
void __afcgi_logmsg(int priority, const char *file, const char *function,
                    int line, char *fmt, ...) {
	va_list ap;
	char buffer[AFCGI_LOG_MSG_BUF];
	char *str_msg;
	char *str_current;
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

	str_current = buffer;
	clen = 0;
	display_two_points = 0;

	// generate time tag
	if((afcgi_log_flags & AFCGI_LOG_DSP_TIME) != 0){
		current_t = time(NULL);
		tm = localtime(&current_t);
		len = snprintf(str_current, AFCGI_LOG_MSG_BUF,
		               "%04d-%02d-%02d %02d:%02d:%02d",
		               tm->tm_year + 1900,
		               tm->tm_mon + 1,
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
		if(display_two_points && 1 < (AFCGI_LOG_MSG_BUF - clen)){
			str_current[0] = ' ';
			str_current++;
			clen++;
		}
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
			len = snprintf(str_current, 128, "[%s] ", file);
			break;
		case AFCGI_LOG_DSP_FUNCTION:
			len = snprintf(str_current, 128, "[%s] ", function);
			break;
		case AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, 128, "[%d] ", line);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_FUNCTION:
			len = snprintf(str_current, 128, "[%s %s] ", function, file);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, 128, "[%s:%d] ", file, line);
			break;
		case AFCGI_LOG_DSP_FUNCTION|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, 128, "[%s %d] ", function, line);
			break;
		case AFCGI_LOG_DSP_FILE|AFCGI_LOG_DSP_FUNCTION|AFCGI_LOG_DSP_LINE:
			len = snprintf(str_current, 128, "[%s %s:%d] ",
			               function, file, line);
			break;
	}
	str_current += len;
	clen += len;
	
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
		write(2, buffer, clen + 1);

	/* remove line feed */
	*p = '\0';

	// out on syslog
	#ifdef AFCGI_USE_SYSLOG
	if((afcgi_log_flags & AFCGI_LOG_SYSLOG) != 0){
		syslog(priority, "%s",  buffer);
	}
	#endif
}
