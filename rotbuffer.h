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

int rotbuffer_read(struct rotbuffer *r, int fd);

#endif
