#include <stdlib.h>
#include <stdio.h>

#if HAVE_USEMARCON
#include <objectlist.h>

CDetails *x(CDetails *p)
{
    return p;
}
#endif

int main(int argc, char **argv)
{
#if HAVE_USEMARCON
    CDetails local;
    CDetails *ptr = new CDetails();

    x(&local);
    x(ptr);

    delete ptr;
#endif
    exit(0);
}
/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

