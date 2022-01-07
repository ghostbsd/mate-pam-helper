# $MCom: pam_helper/Makefile,v 1.2 2008/08/09 07:43:59 marcus Exp $

.include <bsd.own.mk>

PROG=	pam_helper
BINMODE=4555
DPADD=	${LIBPAM}
LDADD=	-lpam
WARNS?=	6

MK_MAN=	no
NO_MAN=	yes

PREFIX?=	/usr/local
BINDIR=		${PREFIX}/bin

.include <bsd.prog.mk>
