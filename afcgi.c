/*
 * Copyright (c) 2009 Thierry FOURNIER
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <events.h>
#include <string.h>

#include "afcgi.h"
#include "rotbuffer.h"

// #define AFCGI_DEBUG

int afcgi_global_maxconn;
static int afcgi_do_close = 0;

enum afcgi_types {
	                               /*  WS->App   management  stream */

	AFCGI_GET_VALUES        =  9,  /*  x         x                  */
	AFCGI_GET_VALUES_RESULT = 10,  /*            x                  */
	AFCGI_UNKNOWN_TYPE      = 11,  /*            x                  */

	AFCGI_BEGIN_REQUEST     =  1,  /*  x                            */
	AFCGI_ABORT_REQUEST     =  2,  /*  x                            */
	AFCGI_END_REQUEST       =  3,
	AFCGI_PARAMS            =  4,  /*  x                     x      */
	AFCGI_STDIN             =  5,  /*  x                     x      */
	AFCGI_DATA              =  8,  /*  x                     x      */
	AFCGI_STDOUT            =  6,  /*                        x      */
	AFCGI_STDERR            =  7   /*                        x      */
};

enum afcgi_status {
	WAIT_HEADER,
	WAIT_REQUEST_HDR,
	WAIT_PARAMS,
	WAIT_AFCGI_STDIN,
	WAIT_AFCGI_DATA
}; 

static void free_afcgi_sess(struct afcgi_sess *s) {
	struct afcgi_hdr *h;
	struct afcgi_hdr *n;

	h = s->hdr;
	while (h != NULL) {
		n = h;
		h = h->next;
		free(n->name);
		free(n->value);
		free(n);
	}
	free(s);
}

static void free_afcgi(struct afcgi *a) {
	int i;

	for (i=0; i<AFCGI_MAX_SESSION; i++)
		if (a->sess[i] != NULL)
			free_afcgi_sess(a->sess[i]);
	free(a);
}

static void conn_close(struct afcgi *a) {
	close(a->fd);
	ev_poll_fd_clr(a->fd, EV_POLL_READ);
	ev_poll_fd_clr(a->fd, EV_POLL_WRITE);
	free_afcgi(a);
}

static void conn_bye(struct afcgi *a) {
	int i;

	for(i=a->max_id; i>=0; i--)
		if (a->sess[i] != NULL && a->sess[i]->on_abort != NULL)
			a->sess[i]->on_abort(a->sess[i], a->sess[i]->arg);

	conn_close(a);
}

static void new_read(int fd, void *arg) {
	int sz;
	struct afcgi *a = arg;
	struct afcgi_sess *s;
	uint8_t ua, ub;
	char *hdr;
	int attr_sz, data_sz;
	struct afcgi_hdr *shdr;

	// retrieve afcgi session
	s = a->sess[a->c.request_id];
	if (s == NULL && a->s != WAIT_HEADER) {
		conn_bye(a);
		return;
	}

	switch ((enum afcgi_status)a->s) {

	/********************************************
	* wait for record header
	********************************************/
	case_WAIT_HEADER:
		a->head = (char *)&a->c;
		a->s = WAIT_HEADER;

	case WAIT_HEADER:
		sz = AFCGI_HEADER_LEN + (char *)&a->c - a->head;
		sz = read(a->fd, a->head, sz);
		if (sz < 0)
			return;

		else if (sz == 0) {	
#ifdef AFCGI_DEBUG
			fprintf(stderr, "Le serveur web a fermé\n");
#endif
			conn_bye(a);
			return;
		}

		else if (sz > 0)
			a->head += sz;

		if (a->head - (char *)&a->c < AFCGI_HEADER_LEN)
			return;

		// adjust values
		ua = ((char *)&a->c)[2];
		ub = ((char *)&a->c)[3];
		a->c.request_id  = ( ua << 8 ) | ub;
		ua = ((char *)&a->c)[4];
		ub = ((char *)&a->c)[5];
		a->c.content_len = ( ua << 8 ) | ub;

#ifdef AFCGI_DEBUG
		char *type;
		switch (a->c.type) {
		case AFCGI_GET_VALUES:        type = "AFCGI_GET_VALUES";        break;
		case AFCGI_GET_VALUES_RESULT: type = "AFCGI_GET_VALUES_RESULT"; break;
		case AFCGI_UNKNOWN_TYPE:      type = "AFCGI_UNKNOWN_TYPE";      break;
		case AFCGI_BEGIN_REQUEST:     type = "AFCGI_BEGIN_REQUEST";     break;
		case AFCGI_ABORT_REQUEST:     type = "AFCGI_ABORT_REQUEST";     break;
		case AFCGI_END_REQUEST:       type = "AFCGI_END_REQUEST";       break;
		case AFCGI_PARAMS:            type = "AFCGI_PARAMS";            break;
		case AFCGI_STDIN:             type = "AFCGI_STDIN";             break;
		case AFCGI_DATA:              type = "AFCGI_DATA";              break;
		case AFCGI_STDOUT:            type = "AFCGI_STDOUT";            break;
		case AFCGI_STDERR:            type = "AFCGI_STDERR";            break;
		default:                      type = "UNKNOWN";                 break;
		}
		fprintf(stderr, "SRV packet header:\n"
		                "  version    : %d\n"
		                "  type       : %s(%d)\n"
		                "  request_id : %d\n"
		                "  content_len: %d\n"
		                "  padding_len: %d\n",
		                a->c.version, type, a->c.type, a->c.request_id,
		                a->c.content_len, a->c.padding_len);
#endif
		// retrieve afcgi session
		s = a->sess[a->c.request_id];
		if (s == NULL && a->c.type != AFCGI_BEGIN_REQUEST) {
			conn_bye(a);
			return;
		}

		// next state
		switch ((enum afcgi_types)a->c.type) {

		case AFCGI_BEGIN_REQUEST:       goto case_WAIT_REQUEST_HDR;
		case AFCGI_PARAMS:              goto case_WAIT_PARAMS;
		case AFCGI_STDIN:               goto case_WAIT_AFCGI_STDIN;
		case AFCGI_DATA:                goto case_WAIT_AFCGI_DATA;
		case AFCGI_ABORT_REQUEST:
		/* value not found in server packets in normal cases */
		case AFCGI_END_REQUEST:
		case AFCGI_STDOUT:
		case AFCGI_STDERR:
		/* TODO */
		case AFCGI_GET_VALUES:
		case AFCGI_GET_VALUES_RESULT:
		/* error */
		case AFCGI_UNKNOWN_TYPE:
		default:
			conn_bye(a);
			return;
		}

	/********************************************
	* wait for begin request header
	********************************************/
	case_WAIT_REQUEST_HDR:

		/* if more than one fastcgi is incoming, and the flag
		 * afcgi_do_close is set, is error. the connection is closed
		 */
		if (afcgi_do_close == 1 && a->max_id != -1) {
			conn_bye(a);
			return;
		}

		// sanity check: the header must be 8 octets
		if (a->c.content_len != 8) {
			conn_bye(a);
			return;
		}
		a->s = WAIT_REQUEST_HDR;

		s = (struct afcgi_sess *)calloc(1, sizeof(struct afcgi_sess));
		if (s == NULL) {
			conn_bye(a);
			return;
		}
		s->head = (char *)&s->h;
		s->request_id = a->c.request_id;
		s->afcgi= a;
		a->sess[s->request_id] = s;
		if (s->request_id > a->max_id)
			a->max_id = s->request_id;

	case WAIT_REQUEST_HDR:
		sz = 8 + (char *)&s->h - s->head;
		sz = read(a->fd, s->head, sz);
		if (sz < 0)
			return;

		else if (sz == 0) {	
			conn_bye(a);
			return;
		}

		else if (sz > 0)
			s->head += sz;

		if (s->head - (char *)&s->h < 8)
			return;

		// adjust values
		ua = ((char *)&s->h)[0];
		ub = ((char *)&s->h)[1];
		s->h.role  = ( ua << 8 ) | ub;

#ifdef AFCGI_DEBUG
		fprintf(stderr, "begin request headers:\n"
		                "  role       : %d\n"
		                "  flags      : 0x%02x\n",
		                s->h.role, s->h.flags);
#endif
		// callback on new
		if (a->binder->on_new != NULL)
			a->binder->on_new(s, a->binder->arg);

		goto case_WAIT_HEADER;

	/********************************************
	* wait for params
	********************************************/
	case_WAIT_PARAMS:
		// bloc vide: fin des headers http
		if (a->c.content_len == 0) {
			if (s->on_headers != NULL)
				s->on_headers(s, s->arg);
			goto case_WAIT_HEADER;
		}
		a->s = WAIT_PARAMS;
		a->buff = a->buffer;
		a->buff_len = 0;

	case WAIT_PARAMS:
		sz = ( a->c.content_len + a->c.padding_len ) - a->buff_len;
		sz = read(a->fd, a->buff, sz);
		if (sz <= 0) {
			conn_bye(a);
			return;
		}

		if (sz > 0)
			a->buff_len += sz;

		if (a->buff_len < ( a->c.content_len + a->c.padding_len ) )
			return;

		// parsing des headers
		a->buff_len = a->c.content_len;
		hdr = a->buffer;

		while(hdr < a->buffer + a->buff_len) {
			char *sa, *sb;

			if ((unsigned char)hdr[0] <= 0x7f) {
				attr_sz = hdr[0];
				hdr++;
			} else {
				attr_sz = ((hdr[0] & 0x7f) << 24) + (hdr[1] << 16) +
				           (hdr[2] << 8) + hdr[3];
				hdr+=4;
			}
			if ((unsigned char)hdr[0] <= 0x7f) {
				data_sz = hdr[0];
				hdr++;
			} else {
				data_sz = ((hdr[0] & 0x7f) << 24) + (hdr[1] << 16) +
				           (hdr[2] << 8) + hdr[3];
				hdr+=4;
			}

			shdr = (struct afcgi_hdr *)malloc(sizeof(struct afcgi_hdr));
			if (shdr == NULL) {
				conn_bye(a);
				return;
			}

			sa = malloc(attr_sz+1);
			if (sa == NULL) {
				free(hdr);
				conn_bye(a);
				return;
			}
			memcpy(sa, hdr, attr_sz);
			sa[attr_sz] = 0;
			hdr += attr_sz;

			sb = malloc(data_sz+1);
			if (sb == NULL) {
				free(sa);
				free(hdr);
				conn_bye(a);
				return;
			}
			memcpy(sb, hdr, data_sz);
			sb[data_sz] = 0;
			hdr += data_sz;

			shdr->name      = sa;
			shdr->name_len  = attr_sz;
			shdr->value     = sb;
			shdr->value_len = data_sz;
			shdr->next      = s->hdr;
			s->hdr          = shdr;

			/*
			fprintf(stderr, "(%d,%d)\t<%s>: <%s>\n", attr_sz, data_sz, sa, sb);
			*/
		}

		goto case_WAIT_HEADER;

	/********************************************
	* wait for params
	********************************************/
	case_WAIT_AFCGI_STDIN:

		// bloc vide: fin des data stdin
		if (a->c.content_len == 0) {
			// call back
			if (s->on_run != NULL)
				s->on_run(s, s->arg);
			goto case_WAIT_HEADER;
		}

		a->s = WAIT_PARAMS;
		a->buff = a->buffer;
		a->buff_len = 0;

	case WAIT_AFCGI_STDIN:

		sz = ( a->c.content_len + a->c.padding_len ) - a->buff_len;
		sz = read(a->fd, a->buff, sz);
		if (sz <= 0) {
			conn_bye(a);
			return;
		}

		if (sz > 0)
			a->buff_len += sz;

		if (a->buff_len < ( a->c.content_len + + a->c.padding_len ) )
			return;

		// callback data ready
		if (s->on_receive != NULL)
			s->on_receive(s, s->arg, a->c.content_len);
		goto case_WAIT_HEADER;

	/********************************************
	* wait for data
	********************************************/
	case_WAIT_AFCGI_DATA:

		// bloc vide: fin des data
		if (a->c.content_len == 0) {
			// call back
			if (s->on_end_of_data != NULL)
				s->on_run(s, s->arg);
			goto case_WAIT_HEADER;
		}

		a->s = WAIT_PARAMS;
		a->buff = a->buffer;
		a->buff_len = 0;

	case WAIT_AFCGI_DATA:
		sz = ( a->c.content_len + a->c.padding_len ) - a->buff_len;
		sz = read(a->fd, a->buff, sz);
		if (sz <= 0) {
			conn_bye(a);
			return;
		}

		if (sz > 0)
			a->buff_len += sz;

		if (a->buff_len < ( a->c.content_len + a->c.padding_len ) )
			return;

		// callback data
		if (s->on_data_recv != NULL)
			s->on_data_recv(s, s->arg, a->c.content_len);
		goto case_WAIT_HEADER;

	}
}

static void new_write(int fd, void *arg) {
	struct afcgi *a = arg;
	struct afcgi_sess *sess;
	char *p, *p2;
	int data;
	int request_id;
	int i;
	
	// try writing
	rotbuffer_write_fd(&a->buff_wr, a->fd);

	// check for end
	while (rotbuffer_free_size(&a->buff_wr) > 24 && a->end != NULL) {

		// build header
		// unsigned char version;
		rotbuffer_add_byte_wc(&a->buff_wr, AFCGI_VERSION);
		// unsigned char type;
		rotbuffer_add_byte_wc(&a->buff_wr, AFCGI_STDOUT);
		// unsigned char requestIdB1;
		// unsigned char requestIdB0;
		rotbuffer_add_byte_wc(&a->buff_wr, a->end->request_id >> 8);
		rotbuffer_add_byte_wc(&a->buff_wr, a->end->request_id & 0x00ff);
		// unsigned char contentLengthB1;
		// unsigned char contentLengthB0;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		// unsigned char paddingLength;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		// unsigned char reserved;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);

#ifdef AFCGI_DEBUG
		fprintf(stderr, "CLI packet header:\n"
		                "  version    : %d\n"
		                "  type       : AFCGI_STDOUT(%d)\n"
		                "  request_id : %d\n"
		                "  content_len: 0\n"
		                "  padding_len: 0\n",
		                AFCGI_VERSION, AFCGI_STDOUT, a->end->request_id);
#endif

		// unsigned char version;
		rotbuffer_add_byte_wc(&a->buff_wr, AFCGI_VERSION);
		// unsigned char type;
		rotbuffer_add_byte_wc(&a->buff_wr, AFCGI_END_REQUEST);
		// unsigned char requestIdB1;
		// unsigned char requestIdB0;
		rotbuffer_add_byte_wc(&a->buff_wr, a->end->request_id >> 8);
		rotbuffer_add_byte_wc(&a->buff_wr, a->end->request_id & 0x00ff);
		// unsigned char contentLengthB1;
		// unsigned char contentLengthB0;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		rotbuffer_add_byte_wc(&a->buff_wr, 8);
		// unsigned char paddingLength;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		// unsigned char reserved;
		rotbuffer_add_byte_wc(&a->buff_wr, 0);

#ifdef AFCGI_DEBUG
		fprintf(stderr, "CLI packet header:\n"
		                "  version    : %d\n"
		                "  type       : AFCGI_END_REQUEST(%d)\n"
		                "  request_id : %d\n"
		                "  content_len: 8\n"
		                "  padding_len: 0\n",
		                AFCGI_VERSION, AFCGI_END_REQUEST, a->end->request_id);
#endif

		// unsigned char appStatusB3;
		// unsigned char appStatusB2;
		// unsigned char appStatusB1;
		// unsigned char appStatusB0;
		rotbuffer_add_byte_wc(&a->buff_wr, (a->end->rc >> 24) & 0xff);
		rotbuffer_add_byte_wc(&a->buff_wr, (a->end->rc >> 16) & 0xff);
		rotbuffer_add_byte_wc(&a->buff_wr, (a->end->rc >>  8) & 0xff);
		rotbuffer_add_byte_wc(&a->buff_wr, (a->end->rc >>  0) & 0xff);
		// unsigned char protocolStatus;
		rotbuffer_add_byte_wc(&a->buff_wr, a->end->return_status);
		// unsigned char reserved[3];
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		rotbuffer_add_byte_wc(&a->buff_wr, 0);
		rotbuffer_add_byte_wc(&a->buff_wr, 0);

		/* update max id */
		if (afcgi_do_close == 0 &&
		    sess->request_id == a->max_id) {
			a->max_id = -1;
			for (i = a->max_id - 1; i >= 0; i--) {
				if (a->sess[i] != NULL) {
					a->max_id = i;
					break;
				}
			}
		}

		// free session
		sess = a->end;
		sess->on_end(sess, sess->arg);
		a->end = a->end->end_next;
		a->sess[sess->request_id] = NULL;
		free_afcgi_sess(sess);

		/* */
		if (afcgi_do_close == 1) {
			conn_close(a);
			return;
		}
	}

	// callback
	while (a->write != NULL) {

		// get session
		sess = a->write;
		request_id = a->write->request_id;

		// move rotbuffer
		// if no space avalaible, return
		if (rotbuffer_free_size(&a->buff_wr) < AFCGI_HEADER_LEN)
			break;
		p = rotbuffer_store(&a->buff_wr);
		rotbuffer_seek_wc(&a->buff_wr, AFCGI_HEADER_LEN);
		p2 = rotbuffer_store(&a->buff_wr);

		// rotate write turn
		a->write = a->write->write_next;

		// callback
		sess->on_write(sess, sess->arg, rotbuffer_free_size(&a->buff_wr));

		// if no data writed
		if (rotbuffer_store(&a->buff_wr) == p2) {
			rotbuffer_seek_wc(&a->buff_wr, - AFCGI_HEADER_LEN);
			break;
		}

		// build header
		// unsigned char version;
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, AFCGI_VERSION);
		// unsigned char type;
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, AFCGI_STDOUT);
		// unsigned char requestIdB1;
		// unsigned char requestIdB0;
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, request_id >> 8);
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, request_id & 0xff);
		// unsigned char contentLengthB1;
		// unsigned char contentLengthB0;
		data = rotbuffer_pos_diff(&a->buff_wr, p2, rotbuffer_store(&a->buff_wr));
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, data >> 8);
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, data & 0xff);
		// unsigned char paddingLength;
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, 0);
		// unsigned char reserved;
		p = rotbuffer_add_byte_at_pos(&a->buff_wr, p, 0);

#ifdef AFCGI_DEBUG
		fprintf(stderr, "CLI packet header:\n"
		                "  version    : %d\n"
		                "  type       : AFCGI_STDOUT(%d)\n"
		                "  request_id : %d\n"
		                "  content_len: %d\n"
		                "  padding_len: 0\n",
		                AFCGI_VERSION, AFCGI_STDOUT, request_id, data);
#endif

	}
}

static void new_conn(int l, void *arg) {
	int fd;
	struct sockaddr_storage addr;
	struct afcgi *a;
	struct afcgi_binder *binder = arg;

	fd = ev_socket_accept(l, &addr);
	a = (struct afcgi *)calloc(1, sizeof(struct afcgi));
	a->fd = fd;
	a->s = WAIT_HEADER;
	a->head = (char *)&a->c;
	a->binder = binder;
	a->write = NULL;
	a->buff_wr.buff = a->buffer_write;
	a->buff_wr.buff_end = a->buff_wr.buff;
	a->buff_wr.buff_start = a->buff_wr.buff;
	a->buff_wr.buff_len = 0;
	a->buff_wr.buff_size = AFCGI_WR_BUFFER_SIZE;
	a->end = NULL;
	a->max_id = -1;
	ev_poll_fd_set(fd, EV_POLL_READ, new_read, a);
}

void afcgi_want_write(struct afcgi_sess *s) {
	struct afcgi_sess *s0;
	if (s->afcgi->write == NULL) {
		s->afcgi->write = s;
		s->write_next = s;
		s->write_prev = s;
	} else {
		s0 = s->afcgi->write;
		s->write_next              = s0;
		s->write_prev              = s0->write_prev;
		s0->write_prev->write_next = s;
		s0->write_prev             = s;
	}
	ev_poll_fd_set(s->afcgi->fd, EV_POLL_WRITE, new_write, s->afcgi);
}

void afcgi_stop_write(struct afcgi_sess *s) {
	if (s->write_next == s) {
		s->afcgi->write = NULL;
		ev_poll_fd_clr(s->afcgi->fd, EV_POLL_WRITE);
	} else {
		s->write_next->write_prev = s->write_prev;
		s->write_prev->write_next = s->write_next;
	}  
}

void afcgi_end(struct afcgi_sess *s, enum afcgi_return_status rs, int rc) {
	s->end_next = s->afcgi->end;
	s->return_status = rs;
	s->rc = rc;
	s->afcgi->end = s;
	afcgi_stop_write(s);
	ev_poll_fd_set(s->afcgi->fd, EV_POLL_WRITE, new_write, s->afcgi);
}

int afcgi_bind(char *bind, afcgi_cb on_new, void *arg) {
	struct afcgi_binder *binder;
	int ret;

	binder = (struct afcgi_binder *)malloc(sizeof(struct afcgi_binder));
	if (binder == NULL)
		return -1;

	ret = ev_socket_bind(bind, afcgi_global_maxconn);
	if (ret < 0) {
		printf("ev_socket_bind fait chier\n");
		exit(1);
	}

	binder->fd      = ret;
	binder->on_new  = on_new;
	binder->arg     = arg;

	ev_poll_fd_set(ret, EV_POLL_READ, new_conn, binder);

	return 0;
}

void afcgi_do_close_socket(void) {
	afcgi_do_close = 1;
}

void afcgi_init(int maxconn, struct ev_timeout_basic_node *tm) {
	afcgi_global_maxconn = maxconn;
	afcgi_do_close = 0;
	poll_select_register();
	ev_timeout_init(tm);
	ev_poll_init(maxconn, tm);
}

void afcgi_loop(int loop) {
	while (1) {
		ev_poll_poll(!loop);
		if (loop == 0)
			break;
	}
}
