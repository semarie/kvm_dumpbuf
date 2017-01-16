
PROG=	kvm_dumpbuf
CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
NOMAN=	1

LDADD+=	-lkvm
DPADD+=	${LIBKVM}

.include <bsd.prog.mk>
