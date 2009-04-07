/*
 * Copyright (c) 2008 Thierry FOURNIER
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License.
 *
 */

/** @file */

#ifndef __AFCGI_H__
#define __AFCGI_H__

#include <stdint.h>
#include <string.h>

#include <events.h>
#include <rotbuffer.h>

#define AFCGI_VERSION 1
#define AFCGI_HEADER_LEN  8
#define AFCGI_RD_BUFFER_SIZE (1<<16)
#define AFCGI_WR_BUFFER_SIZE (1<<16)
#define AFCGI_MAX_SESSION (1<<16)

/** The names of the different callbacks */
enum afcgi_callback_names {
	/** Called when all headers was received */
	ON_HEADERS = 0,
	/** Called when STDIN stream packet was ready */
	ON_RECEIVE,
	/** Called when DATA stream packet was ready */
	ON_DATA_RECV,
	/** Called when all STDIN packets was sent */
	ON_RUN,
	/** Called when all DATA packets was sent */
	ON_END_OF_DATA,
	/** Called when application can write on STDIN, STDERR */
	ON_WRITE,
	/** Called before destorying fastcgi session */
	ON_END,
	/** Called when server sent abort */
	ON_ABORT
};

/** return status */
enum afcgi_return_status {
	/** normal end of request. */
	AFCGI_REQUEST_COMPLETE = 0,

	/** 
	 * rejecting a new request. This happens when a Web server sends concurrent
	 * requests over one connection to an application that is designed to
	 * process one request at a time per connection.
	 */
	AFCGI_CANT_MPX_CONN    = 1,

	/**
	 * rejecting a new request. This happens when the application runs out of
	 * some resource, e.g. database connections.
	 */
	AFCGI_OVERLOADED       = 2,

	/**
	 * rejecting a new request. This happens when the Web server has
	 * specified a role that is unknown to the application.
	 */
	AFCGI_UNKNOWN_ROLE     = 3
};

struct afcgi_sess;
struct afcgi;

/** 
 * used for standard afcgi callbacks
 * @param s   is afcgi session
 * @param arg is easy argument
 */
typedef void (*afcgi_cb)(struct afcgi_sess *s, void *arg);

/** 
 * used for standard afcgi input callbacks
 * @param s    is afcgi session
 * @param arg  is easy argument
 * @param len  is data length
 */
typedef void (*afcgi_cb_data)(struct afcgi_sess *s, void *arg,
                              int len);

struct afcgi_hdr {
	char *name;
	int name_len;
	char *value;
	int value_len;
	struct afcgi_hdr *next;
};

struct afcgi_sess {
	uint16_t request_id;
	struct {
		uint16_t role;
		uint8_t  flags;
		uint8_t  reserved[5];
	} h;
	char *head;
	struct afcgi_hdr *hdr;
	enum afcgi_return_status return_status;
	int rc;

	// call backs
	void *arg;
	afcgi_cb on_headers;
	afcgi_cb_data on_receive;
	afcgi_cb_data on_data_recv;
	afcgi_cb on_end_of_data;
	afcgi_cb on_run;
	afcgi_cb on_abort;
	afcgi_cb_data on_write;
	afcgi_cb on_end;

	// links
	struct afcgi *afcgi;
	struct afcgi_sess *write_next;
	struct afcgi_sess *write_prev;
	struct afcgi_sess *end_next;
};

struct afcgi {
	int fd;
	int s;
	struct { // current header
		uint8_t  version;
		uint8_t  type;
		uint16_t request_id;
		uint16_t content_len;
		uint8_t  padding_len;
		uint8_t  reserved;
	} c;
	char *head;
	struct afcgi_binder *binder;
	struct afcgi_sess *sess[AFCGI_MAX_SESSION];

	// read
	char buffer[AFCGI_RD_BUFFER_SIZE];
	char *buff;
	int buff_len;

	// write
	struct afcgi_sess *write;
	struct rotbuffer buff_wr;
	char buffer_write[AFCGI_WR_BUFFER_SIZE];

	// end
	struct afcgi_sess *end;
};

struct afcgi_binder {
	int fd;
	void *arg;
	afcgi_cb on_new;
};

/**
 * init fcgi internals and poller system
 * @param maxconn The maximun of connection expected (all sockets)
 *                -1: use the max limit (ulimit -n)
 *                >0: use this value, ans set limit
 * @param tm      The timeout tree pointer from lib events
 */
void afcgi_init(int maxconn, struct ev_timeout_basic_node *tm);

/**
 * Bind network address or socket 
 * @param bind   network address or socket (or NULL for stdin)
 * @param on_new callback called for new connexion
 * @param arg    easy arg 
 * @return if ok return 0, else return < 0
 */
int afcgi_bind(char *bind, afcgi_cb on_new, void *arg);

/**
 * afcgi main loop. This launched the main loop after initialization
 * @param loop (boolean) 0: the function return,
 *                       1: the function never return
 */
void afcgi_loop(int loop);

/**
 * set easy argument
 * @param s fascgi session identifier
 * @param arg easy argument
 */
static inline void afcgi_set_arg(struct afcgi_sess *s, void *arg) { s->arg = arg; }

/**
 * set callback
 * @param sess fascgi session identifier
 * @param name callback name
 * @param cb calback pointer
 */
#define afcgi_set_callback(sess, name, cb) afcgi_set_cb_ ## name(sess, cb)

static inline void 
afcgi_set_cb_ON_HEADERS(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_headers = cb;
}
static inline void 
afcgi_set_cb_ON_RECEIVE(struct afcgi_sess *s, afcgi_cb_data cb) {
	s->on_receive = cb;
}
static inline void 
afcgi_set_cb_ON_DATA_RECV(struct afcgi_sess *s, afcgi_cb_data cb) {
	s->on_receive = cb;
}
static inline void 
afcgi_set_cb_ON_WRITE(struct afcgi_sess *s, afcgi_cb_data cb) {
	s->on_write = cb;
}
static inline void 
afcgi_set_cb_ON_RUN(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_run = cb;
}
static inline void 
afcgi_set_cb_ON_END_OF_DATA(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_end_of_data = cb;
}
static inline void 
afcgi_set_cb_ON_END(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_end = cb;
}
static inline void 
afcgi_set_cb_ON_ABORT(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_abort = cb;
}

/**
 * search header
 * @param s afcgi session identifier
 * @param name header name (case insensitive
 * @return header if found, NULL if not found
 */
static inline struct afcgi_hdr *
afcgi_search_header(struct afcgi_sess *s, char *name) {
	struct afcgi_hdr *h;

	for (h = s->hdr; h != NULL; h = h->next)
		if(strcasecmp(name, h->name) == 0)
			return h;
	return NULL;
}

/**
 * search header, return string format
 * @param s afcgi session identifier
 * @param name header name (case insensitive
 * @return char *header if found, NULL if not found
 */
static inline char *
afcgi_search_header_str(struct afcgi_sess *s, char *name) {
	struct afcgi_hdr *h;

	h = afcgi_search_header(s, name);
	if (h == NULL)
		return NULL;
	return h->value;
}

/**
 * afcgi session want's write
 * @param s afcgi session identifier
 */
void afcgi_want_write(struct afcgi_sess *s);

/**
 * afcgi session do not write more
 * @param s afcgi session identifier
 */
void afcgi_stop_write(struct afcgi_sess *s);

/**
 * write data
 * @param s afcgi session identifier
 * @param buff buffer
 * @param len buffer len
 * @return size writed
 */
static inline int afcgi_write(struct afcgi_sess *s, const char *buff, int len) {
	return rotbuffer_read_buff(&s->afcgi->buff_wr, buff, len);
}

/**
 * afcgi session end
 * @param s afcgi session identifier
 * @param rs return status
 * @param rc return code
 */
void afcgi_end(struct afcgi_sess *s, enum afcgi_return_status rs, int rc);

/* log priority.
 * the same level that syslog
 */
#ifndef LOG_EMERG
/** log emergency */
#	define LOG_EMERG       0
#endif

#ifndef LOG_ALERT
/** log alert */
#	define LOG_ALERT       1
#endif

#ifndef LOG_CRIT
/** log critical */
#	define LOG_CRIT        2
#endif

#ifndef LOG_ERR
/** log error */
#	define LOG_ERR         3
#endif

#ifndef LOG_WARNING
/** log warning */
#	define LOG_WARNING     4
#endif

#ifndef LOG_NOTICE
/** log notice */
#	define LOG_NOTICE      5
#endif

#ifndef LOG_INFO
/** log info */
#	define LOG_INFO        6
#endif

#ifndef LOG_DEBUG
/** log debug */
#	define LOG_DEBUG       7
#endif

#ifndef AFCGI_MAX_LOG_LEVEL
/**
 * all debug logs with level > AFCGI_MAX_LOG_LEVEL are not compiled
 * redifine this define with compilation option for build binary in
 * debug mode or in normal mode
 */
#	define AFCGI_MAX_LOG_LEVEL LOG_WARNING
#endif

/** 
 * send log message.
 * is recomended to use for compilation code simplification
 *
 * @param priority log level from LOG_DEBUG to LOG_EMERG
 * @param fmt log format: ex: "open file %s"
 * @param args... args for log format
 */
#define afcgi_logmsg(priority, fmt, args...) \
	do { \
		if ( (priority) <= AFCGI_MAX_LOG_LEVEL ) { \
			__afcgi_logmsg((priority), \
	                      __FILE__, __FUNCTION__, __LINE__, fmt, ##args); \
		} \
	} while(0)

/** 
 * send log message.
 * is recomended to use macro
 *
 * @param priority log level from LOG_DEBUG to LOG_EMERG
 * @param file code filename
 * @param function code function
 * @param line code line
 * @param fmt log format: ex: "open file %s"
 * @param args args for log format
 */
void __afcgi_logmsg(int priority, const char *file,
                    const char *function, int line, char *fmt, ...);


#define AFCGI_LOG_STDERR        0x00000001
#define AFCGI_LOG_DSP_FUNCTION  0x00000004
#define AFCGI_LOG_DSP_FILE      0x00000010
#define AFCGI_LOG_DSP_LINE      0x00000020
#define AFCGI_LOG_DSP_HOSTNAME  0x00000040
#define AFCGI_LOG_DSP_APP_NAME  0x00000080
#define AFCGI_LOG_DSP_PID       0x00000100
#define AFCGI_LOG_DSP_TIME      0x00000200
#define AFCGI_LOG_SYSLOG        0x00000400
#define AFCGI_LOG_DSP_LOG_LEVEL 0x00001000

/** 
 * set log modes
 * 
 * @param flags:  can takes this values:
 *
 *  - AFCGI_LOG_STDERR log on stderr output
 *  - AFCGI_LOG_SYSLOG log on syslog, this option require 3 parameters
 *     - (char *) program name (generally the same AFCGI_LOG_DSP_APP_NAME)
 *     - (int) log pid ? : 1=>yes, 0=>no
 *     - (int) the facility code:
 *         - LOG_KERN     : kernel messages 
 *         - LOG_USER     : random user-level messages 
 *         - LOG_MAIL     : mail system 
 *         - LOG_DAEMON   : system daemons 
 *         - LOG_AUTH     : security/authorization messages 
 *         - LOG_SYSLOG   : messages generated internally by syslogd 
 *         - LOG_LPR      : line printer subsystem 
 *         - LOG_NEWS     : network news subsystem 
 *         - LOG_UUCP     : UUCP subsystem 
 *         - LOG_CRON     : clock daemon 
 *         - LOG_AUTHPRIV : security/authorization messages (private) 
 *         - LOG_FTP      : ftp daemon 
 *         - LOG_LOCAL0   : reserved for local use 
 *         - LOG_LOCAL1   : reserved for local use 
 *         - LOG_LOCAL2   : reserved for local use 
 *         - LOG_LOCAL3   : reserved for local use 
 *         - LOG_LOCAL4   : reserved for local use 
 *         - LOG_LOCAL5   : reserved for local use 
 *         - LOG_LOCAL6   : reserved for local use 
 *         - LOG_LOCAL7   : reserved for local use 
 *
 *  - AFCGI_LOG_DSP_LOG_LEVEL display only loglevel upper than the parameter.
 *                            This option require 1 parameter: 
 *     - (int) loglevel. default: LOG_WARNING
 *
 *  - AFCGI_LOG_DSP_TIME      display time in log
 *  - AFCGI_LOG_DSP_HOSTNAME  display hostname in log
 *  - AFCGI_LOG_DSP_APP_NAME  display application name in log.
 *                            This option require 1 parameter
 *     - (char *) application name
 *
 *  - AFCGI_LOG_DSP_PID       display application pid in log
 *  - AFCGI_LOG_DSP_FUNCTION: log msg function name (generally used for debug)
 *  - AFCGI_LOG_DSP_FILE:     log msg filename (generally used for debug)
 *  - AFCGI_LOG_DSP_LINE:     log msg line (generallyused for debug)
 */
void afcgi_set_log_opt(uint32_t flags, ...);

#endif

