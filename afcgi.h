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

#include <events.h>

#define AFCGI_VERSION 1
#define AFCGI_HEADER_LEN  8
#define AFCGI_BUFFER_SIZE (1<<16)

/** The names of the different callbacks */
enum afcgi_callback_names {
	ON_HEADERS = 0,
	ON_RECEIVE,
	ON_RUN,
	ON_WRITE,
	ON_ABORT
};

struct ev_timeout_basic_node tm;

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
 * @param data is buffer containing data
 * @param len  is data length
 */
typedef void (*afcgi_cb_data)(struct afcgi_sess *s, void *arg,
                              char *data, int len);

/** 
 * used for standard afcgi output callbacks
 * @param s    is afcgi session
 * @param arg  is easy argument
 * @param data is buffer receiving data
 * @param len  is max data length writable
 * @return     return length writed
 */
typedef int (*afcgi_cb_write)(struct afcgi_sess *s, void *arg,
                              char *data, int len);

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

	// call backs
	void *arg;
	afcgi_cb on_headers;
	afcgi_cb_data on_receive;
	afcgi_cb on_run;
	afcgi_cb on_abort;
	afcgi_cb_write on_write;

	// links
	struct afcgi *afcgi;
	struct afcgi_sess *write_next;
	struct afcgi_sess *write_prev;
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
	char buffer[1<<16];
	char *buff;
	int buff_len;
	struct afcgi_binder *binder;
	struct afcgi_sess *sess[AFCGI_BUFFER_SIZE];

	// write
	struct afcgi_sess *write;
	char write_buffer[AFCGI_BUFFER_SIZE];
	int write_len;
	char *write_start;
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
 */
void afcgi_init(int maxconn);

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
afcgi_set_cb_ON_WRITE(struct afcgi_sess *s, afcgi_cb_write cb) {
	s->on_write = cb;
}
static inline void 
afcgi_set_cb_ON_RUN(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_run = cb;
}
static inline void 
afcgi_set_cb_ON_ABORT(struct afcgi_sess *s, afcgi_cb cb) {
	s->on_abort = cb;
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

#endif
