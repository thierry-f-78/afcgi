#include <stdio.h>
#include <errno.h>
#include <sys/uio.h>

#include "rotbuffer.h"

int rotbuffer_read_fd(struct rotbuffer *r, int fd) {
	struct iovec vector[2];
	char *theo_end;
	int vector_nb;
	int len;

	// cant read data because the buffer is full
	if (r->buff_len == r->buff_size)
		return 0;

	// circular buffer vectors
	theo_end = r->buff_end + r->buff_size - r->buff_len;

	// one vector
	if (theo_end <= r->buff + r->buff_size) {
		vector_nb			 = 1;
		vector[0].iov_base = r->buff_end;
		vector[0].iov_len  = theo_end - r->buff_end;
	}

	// two vectors (rotate)
	else {
		vector_nb			 = 2;
		vector[0].iov_base = r->buff_end;
		vector[0].iov_len  = r->buff + r->buff_size - r->buff_end;
		vector[1].iov_base = r->buff;
		vector[1].iov_len  = r->buff_size - r->buff_len - vector[0].iov_len;
	}	
	
	// read data
	len = readv(fd, (const struct iovec *)&vector, vector_nb);

	// read error
	if (len == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		else
			return -1;
	}

	// update circular buffer ptrs
	r->buff_end += len;
	r->buff_len += len;
	if (r->buff_end >= r->buff + r->buff_size)
		r->buff_end -= r->buff_size;

	return 0;
}

int rotbuffer_write_fd(struct rotbuffer *r, int fd) {
	struct iovec vector[2];
	int vector_nb;
	int len;
	
	// nothing to write
	if (r->buff_len == 0)
		return 0;

	// find writing vector
	// one vector case
	if (r->buff_start < r->buff_end) {
		vector_nb          = 1;
		vector[0].iov_base = r->buff_start;
		vector[0].iov_len  = r->buff_len;
	}
	// two vectors case
	else {
		vector_nb          = 2;
		vector[0].iov_base = r->buff_start;
		vector[0].iov_len  = r->buff + r->buff_size - r->buff_start;
		vector[1].iov_base = r->buff;
		vector[1].iov_len  = r->buff_len - vector[0].iov_len;
	}

	// writing datas for the client
	len = writev(fd, (const struct iovec *)&vector, vector_nb);

	// writing errors
	if (len == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return 0;

		// in real error case
		return -1;
	}

	// update buffer
	r->buff_len -= len;
	if (r->buff_len == 0) {
		r->buff_start = r->buff;
		r->buff_end   = r->buff;
	}
	else {
		r->buff_start += len;
		if (r->buff_start >= r->buff + r->buff_size)
			r->buff_start -= r->buff_size;
	}
	return 0;
}
