/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyleft Daniele Lacamera 2005-2007
 * Copyleft Dan Kruchinin <dkruchinin@gmail.com> 2010
 * See AUTHORS and COPYING before using this software.
 *
 *
 *
 */

#include <string.h>
#include <assert.h>
#include <sys/mman.h>

#include "pepdefs.h"
#include "pepsal.h"
#include "pepbuf.h"

int pepbuf_init(struct pep_buffer *pbuf)
{
    void *space;

    space = mmap(NULL, PEPBUF_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (!space) {
        return -1;
    }

    pbuf->space = space;
    pbuf->r_pos = pbuf->w_pos = pbuf->space;
    pbuf->total_size = PEPBUF_PAGES * PAGE_SIZE;
    pbuf->space_left = pbuf->total_size;
    pbuf->rbytes = 0;

    return 0;
}

void pepbuf_deinit(struct pep_buffer *pbuf)
{
    munmap(pbuf->space, pbuf->total_size);
    memset(pbuf, 0, sizeof(*pbuf));
}

void pepbuf_update_rpos(struct pep_buffer *pbuf, ssize_t rb)
{
    assert((ssize_t)PEPBUF_SPACE_LEFT(pbuf) - rb >= 0);
    pbuf->r_pos += rb;
    pbuf->rbytes += rb;
    pbuf->space_left -= rb;
}

void pepbuf_update_wpos(struct pep_buffer *pbuf, ssize_t wb)
{
    assert(((pbuf->w_pos + wb) - (char *)pbuf->space) <= pbuf->total_size);

    pbuf->w_pos += wb;
    pbuf->rbytes -= wb;
    if (pbuf->w_pos == pbuf->r_pos) {
        pbuf->r_pos = pbuf->w_pos = pbuf->space;
        pbuf->space_left = pbuf->total_size;
    }
}
