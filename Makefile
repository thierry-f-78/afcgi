CPPFLAGS = 
CFLAGS = -I../events/ -I../rotbuffer/ -O0 -g -Wall
LDFLAGS = -L../events/ -levents -L../rotbuffer/ -lrotbuffer

OBJS = afcgi.o afcgi_logmsg.o

libafcgi.a: $(OBJS)
	$(AR) -rcv libafcgi.a $(OBJS)

clean:
	rm -f libafcgi.a $(OBJS)

doc:
	doxygen afcgi.doxygen
 
cleandoc:
	rm -rf html man

