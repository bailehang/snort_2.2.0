/* $Id: inet_aton.c,v 1.1 2003/12/03 15:22:23 chris_reid Exp $ */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


/* Convert from "a.b.c.d" IP address string into
 * an in_addr structure.  Returns 0 on failure,
 * and 1 on success.
 */
int inet_aton(const char *cp, struct in_addr *addr)
{
    if( cp==NULL || addr==NULL )
    {
        return(0);
    }

    addr->s_addr = inet_addr(cp);
    return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}
