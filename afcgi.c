#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <events.h>
#include <string.h>

#include "afcgi.h"
#include "btree32.h"

int afcgi_global_maxconn;

enum afcgi_types {
	AFCGI_BEGIN_REQUEST     =  1,
	AFCGI_ABORT_REQUEST     =  2,
	AFCGI_END_REQUEST       =  3,
	AFCGI_PARAMS            =  4,
	AFCGI_STDIN             =  5,
	AFCGI_STDOUT            =  6,
	AFCGI_STDERR            =  7,
	AFCGI_DATA              =  8,
	AFCGI_GET_VALUES        =  9,
	AFCGI_GET_VALUES_RESULT = 10
};

enum afcgi_status {
	WAIT_HEADER,
	WAIT_REQUEST_HDR,
	WAIT_PARAMS,
	WAIT_AFCGI_STDIN
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
	struct btree32 *b;
	struct afcgi_sess *s;

	while (1) {
		b = btree32_get_min((struct btree32_node *)&a->tb);
		if (b == NULL)
			break;
		btree32_remove(b);
		s = btree32_get_data(b, struct afcgi_sess *);
		free_afcgi_sess(s);
		free(b);
	}
	free(a);
}

static void conn_bye(struct afcgi *a) {
	close(a->fd);
	ev_poll_fd_clr(a->fd, EV_POLL_READ);
	ev_poll_fd_clr(a->fd, EV_POLL_WRITE);
	free_afcgi(a);
}

static void new_read(int fd, void *arg) {
	int sz;
	struct afcgi *a = arg;
	struct afcgi_sess *s;
	uint8_t ua, ub;
	char *hdr;
	int attr_sz, data_sz;
	struct btree32 *bt;
	int ret;
	struct afcgi_hdr *shdr;

	switch ((enum afcgi_status)a->s) {

	/********************************************
	* wait for record header
	********************************************/
	case_WAIT_HEADER:
		a->head = (char *)&a->c;
		a->s = WAIT_HEADER;

	case WAIT_HEADER:
		sz = FCGI_HEADER_LEN + (char *)&a->c - a->head;
		sz = read(a->fd, a->head, sz);
		if (sz < 0)
			return;

		else if (sz == 0) {	
			conn_bye(a);
			return;
		}

		else if (sz > 0)
			a->head += sz;

		if (a->head - (char *)&a->c < FCGI_HEADER_LEN)
			return;

		// adjust values
		ua = ((char *)&a->c)[2];
		ub = ((char *)&a->c)[3];
		a->c.request_id  = ( ua << 8 ) | ub;
		ua = ((char *)&a->c)[4];
		ub = ((char *)&a->c)[5];
		a->c.content_len = ( ua << 8 ) | ub;

		fprintf(stderr, "Headers:       \n"
		                "  version    : %d\n"
		                "  type       : %d\n"
		                "  request_id : %d\n"
		                "  content_len: %d\n"
		                "  padding_len: %d\n",
		                a->c.version, a->c.type, a->c.request_id,
		                a->c.content_len, a->c.padding_len);

		// next state
		switch ((enum afcgi_types)a->c.type) {

		case AFCGI_BEGIN_REQUEST:       goto case_WAIT_REQUEST_HDR;
		case AFCGI_PARAMS:              goto case_WAIT_PARAMS;
		case AFCGI_STDIN:               goto case_WAIT_AFCGI_STDIN;
		case AFCGI_ABORT_REQUEST:
		case AFCGI_END_REQUEST:
		case AFCGI_STDOUT:
		case AFCGI_STDERR:
		case AFCGI_DATA:
		case AFCGI_GET_VALUES:
		case AFCGI_GET_VALUES_RESULT:
			conn_bye(a);
			return;
		}

	/********************************************
	* wait for begin request header
	********************************************/
	case_WAIT_REQUEST_HDR:

		// sanity check: the header must be 8 octets
		if (a->c.content_len != 8) {
			conn_bye(a);
			return;
		}
		a->s = WAIT_REQUEST_HDR;

		s = (struct afcgi_sess *)malloc(sizeof(struct afcgi_sess));
		if (s == NULL) {
			conn_bye(a);
			return;
		}
		s->hdr = NULL;
		s->head = (char *)&s->h;
		s->request_id = a->c.request_id;
		s->arg = NULL;
		s->on_headers = NULL;
		s->on_receive = NULL;
		s->on_run = NULL;
		s->on_abort = NULL;

		bt = btree32_new();
		if (bt == NULL) {
			conn_bye(a);
			return;
		}
		btree32_build(bt, s->request_id, s);
		ret = btree32_insert((struct btree32_node *)&a->tb, bt, 0);
		if (ret != 0) {
			conn_bye(a);
			return;
		}

	case WAIT_REQUEST_HDR:
		bt = btree32_exists((struct btree32_node *)&a->tb, s->request_id);
		if (bt == NULL) {
			conn_bye(a);
			return;
		}
		s = btree32_get_data(bt, struct afcgi_sess *);

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

		fprintf(stderr, "begin request headers:\n"
		                "  role       : %d\n"
		                "  flags      : 0x%02x\n",
		                s->h.role, s->h.flags);

		// callback on new
		a->binder->on_new(s, a->binder->arg);

		goto case_WAIT_HEADER;

	/********************************************
	* wait for params
	********************************************/
	case_WAIT_PARAMS:
		// bloc vide: fin des headers http
		if (a->c.content_len == 0)
			goto case_WAIT_HEADER;
		a->s = WAIT_PARAMS;
		a->buff = a->buffer;
		a->buff_len = 0;

	case WAIT_PARAMS:

		bt = btree32_exists((struct btree32_node *)&a->tb, s->request_id);
		if (bt == NULL) {
			conn_bye(a);
			return;
		}
		s = btree32_get_data(bt, struct afcgi_sess *);

		sz = a->c.content_len - a->buff_len;
		sz = read(a->fd, a->buff, sz);
		if (sz <= 0) {
			conn_bye(a);
			return;
		}

		if (sz > 0)
			a->buff_len += sz;

		if (a->buff_len < a->c.content_len)
			return;

		// parsing des headers
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
			s->hdr          = shdr->next;

			fprintf(stderr, "(%d,%d)\t<%s>: <%s>\n", attr_sz, data_sz, sa, sb);
		}

		goto case_WAIT_HEADER;

	/********************************************
	* wait for params
	********************************************/
	case_WAIT_AFCGI_STDIN:
	case WAIT_AFCGI_STDIN:
		goto case_WAIT_HEADER;
	}

}

static void new_conn(int l, void *arg) {
	int fd;
	struct sockaddr_storage addr;
	struct afcgi *a;
	struct afcgi_binder *binder = arg;

	fd = ev_socket_accept(l, &addr);
	a = (struct afcgi *)malloc(sizeof(struct afcgi));
	a->fd = fd;
	a->s = WAIT_HEADER;
	a->head = (char *)&a->c;
	a->binder = binder;
	btree32_init_base((struct btree32_node *)&a->tb);
	ev_poll_fd_set(fd, EV_POLL_READ, new_read, a);
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

void afcgi_init(int maxconn) {
	afcgi_global_maxconn = maxconn;
	poll_select_register();
	ev_timeout_init(&tm);
	ev_poll_init(maxconn, &tm);
}

void afcgi_loop(int loop) {
	while (1) {
		ev_poll_poll();
		if (loop == 0)
			break;
	}
}
