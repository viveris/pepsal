
/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@google.com> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#ifndef __PEPSAL_H
#define __PEPSAL_H

#include "pepdefs.h"
#include "pepbuf.h"
#include "atomic.h"
#include "list.h"

enum proxy_status {
    PST_CLOSED = 0,
    PST_OPEN,
    PST_CONNECT,
    PST_PENDING,
    PST_INVAL,
};

/* I/O flags of PEP endpoint */
#define PEP_IORDONE 0x01
#define PEP_IOWDONE 0x02
#define PEP_IOEOF   0x04
#define PEP_IOERR   0x08

struct pep_proxy;

struct pep_endpoint{
	int addr;
	unsigned short port;
    int fd;
    struct pep_buffer buf;
    struct pep_proxy *owner;
    unsigned short poll_events;
    unsigned char iostat;
};

#define PROXY_ENDPOINTS 2

struct pep_proxy {
	enum proxy_status status;
    struct list_node lnode;
    struct list_node qnode;

    union {
        struct pep_endpoint endpoints[PROXY_ENDPOINTS];
        struct {
            struct pep_endpoint src;
            struct pep_endpoint dst;
        };
    };

    time_t syn_time;
    time_t last_rxtx;
    atomic_t refcnt;
    int enqueued;
};

#endif /* !__PEPSAL_H */
