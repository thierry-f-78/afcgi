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

#define FCGI_HEADER_LEN  8

/** The names of the different callbacks */
enum afcgi_callback_names {
	ON_HEADERS = 0,
	ON_RECEIVE,
	ON_RUN,
	ON_ABORT
};

struct ev_timeout_basic_node tm;

struct afcgi_sess;

typedef void (*afcgi_cb)(struct afcgi_sess *s, void *arg);

struct afcgi_binder {
	int fd;
	void *arg;
	afcgi_cb on_new;
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
	char tb[24];
};

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
	afcgi_cb on_receive;
	afcgi_cb on_run;
	afcgi_cb on_abort;
};

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

static inline void afcgi_set_cb_ON_HEADERS(struct afcgi_sess *s, afcgi_cb cb){
	s->on_headers = cb;
}
static inline void afcgi_set_cb_ON_RECEIVE(struct afcgi_sess *s, afcgi_cb cb){
	s->on_receive = cb;
}
static inline void afcgi_set_cb_ON_RUN(struct afcgi_sess *s, afcgi_cb cb){
	s->on_run = cb;
}
static inline void afcgi_set_cb_ON_ABORT(struct afcgi_sess *s, afcgi_cb cb){
	s->on_abort = cb;
}

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

#endif
