#
# File          : Makefile
# Description   : Build file for CSE543 project 1, applied cryptography
#                 


# Environment Setup
LIBDIRS=-L. -L/usr/lib64/
INCLUDES=-I. -I/usr/include/
CC=gcc 
CFLAGS=-c $(INCLUDES) -g -Wall
LINK=gcc -g
LDFLAGS=$(LIBDIRS)
AR=ar rc
RANLIB=ranlib

# Suffix rules
.c.o :
	${CC} ${CFLAGS} $< -o $@

#
# Setup builds

TARGETS=cse543-p1 \
	cse543-p1-server
CSE543CRLIB=cse543-crlib
CSE543CRLIBOBJS=cse543-proto.o \
		 cse543-network.o \
		 cse543-ssl.o \
		 cse543-util.o 
LIBS=-lcrypto -lm 

#
# Project Protections

p1 : $(TARGETS)

cse543-p1 : cse543-p1.o lib$(CSE543CRLIB).a
	$(LINK) $(LDFLAGS) cse543-p1.o $(LIBS) -l$(CSE543CRLIB) -o $@

cse543-p1-server : cse543-p1.o lib$(CSE543CRLIB).a
	$(CC) $(CFLAGS) cse543-p1.c -DCSE543_PROTOCOL_SERVER -o cse543-p1-server.o 
	$(LINK) $(LDFLAGS) cse543-p1-server.o $(LIBS) -l$(CSE543CRLIB) -o $@

lib$(CSE543CRLIB).a : $(CSE543CRLIBOBJS)
	$(AR) $@ $(CSE543CRLIBOBJS)
	$(RANLIB) $@

clean:
	rm -f *.o *~ $(TARGETS) lib$(CSE543CRLIB).a

BASENAME=CSE543_SSH
tar: 
	tar cvfz $(BASENAME).tgz -C ..\
	    $(BASENAME)/Makefile \
            $(BASENAME)/cse543-p1.c \
	    $(BASENAME)/cse543-proto.c \
	    $(BASENAME)/cse543-proto.h \
	    $(BASENAME)/cse543-network.c \
	    $(BASENAME)/cse543-network.h \
	    $(BASENAME)/cse543-ssl.c \
	    $(BASENAME)/cse543-ssl.h \
	    $(BASENAME)/cse543-util.c \
	    $(BASENAME)/cse543-util.h \
            $(BASENAME)/SSH_Specification.pdf \
	    $(BASENAME)/shared 

