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
