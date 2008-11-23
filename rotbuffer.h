#ifndef __ROTBUFFER_H__
#define __ROTBUFFER_H__

struct rotbuffer {
	char *buff_end;
	char *buff_start;
	int buff_len;
	int buff_size;
	char buff[1];
};

#define struct_rotbuffer(__name, __size) \
	struct rotbuffer { \
		char *buff_end; \
		char *buff_start; \
		int buff_len; \
		int buff_size; \
		char buff[__size]; \
	} __name;

int rotbuffer_read_fd(struct rotbuffer *r, int fd);
int rotbuffer_write_fd(struct rotbuffer *r, int fd);
static inline int rotbuffer_add_byte(struct rotbuffer *r, char c) {
	if (r->buff_len + 1 > r->buff_size)
		return 0;
	*r->buff_end = c;
	r->buff_end++;
	r->buff_len++;
	if (r->buff_end >= r->buff + r->buff_size)
		r->buff_end = r->buff;
	return 1;
}
static inline void rotbuffer_add_byte_wc(struct rotbuffer *r, char c) {
	*r->buff_end = c;
	r->buff_end++;
	r->buff_len++;
	if (r->buff_end >= r->buff + r->buff_size)
		r->buff_end = r->buff;
}
static inline int rotbuffer_free_size(struct rotbuffer *r) {
	return r->buff_size - r->buff_len;
}
static inline char *rotbuffer_store_and_seek(struct rotbuffer *r, int seek) {
	if (r->buff_len + seek > r->buff_size)
		return NULL;
	char *a = r->buff_end;
	r->buff_len += seek;
	r->buff_end += seek;
	return a;
}

#endif
