#
# crypto/lwekex/Makefile
#

DIR=	lwekex
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=lwekextest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	lwekex_key.c lwekex_err.c

LIBOBJ=	lwekex_key.o lwekex_err.o

SRC= $(LIBSRC)

EXHEADER= lwekex.h
HEADER=	lwekex_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

generate_a: generate_a.c
	gcc -o generate_a generate_a.c $(INCLUDES) -L$(TOP) -lcrypto -ldl
	./generate_a ${FILE}

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

lwekex_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
lwekex_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lwekex_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
lwekex_err.o: ../../include/openssl/opensslconf.h
lwekex_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lwekex_err.o: ../../include/openssl/rlwekex.h ../../include/openssl/safestack.h
lwekex_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
lwekex_err.o: lwekex_err.c
lwekex_key.o: ../../include/openssl/aes.h ../../include/openssl/bio.h
lwekex_key.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
lwekex_key.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
lwekex_key.o: ../../include/openssl/lhash.h ../../include/openssl/lwekex.h
lwekex_key.o: ../../include/openssl/opensslconf.h
lwekex_key.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lwekex_key.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
lwekex_key.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
lwekex_key.o: lwekex_key.c lwekex_locl.h lwekexlib/lwe.c lwekexlib/lwe.h
lwekex_key.o: lwekexlib/lwe_a.h lwekexlib/lwe_table.h
