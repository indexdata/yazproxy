/* $Id: mod_sample.cpp,v 1.1 2005-02-11 15:19:08 adam Exp $
   Copyright (c) 1998-2005, Index Data.

This file is part of the yaz-proxy.

YAZ proxy is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

YAZ proxy is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with YAZ proxy; see the file LICENSE.  If not, write to the
Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.
 */

#include <string.h>
#include <stdio.h>

#include <yazproxy/module.h>

void *my_init(void)
{
    return 0;  // no private data for handler
}

void my_destroy(void *p)
{
    // private data destroy
}

int my_authenticate(void *p, const char *user, const char *group,
		    const char *password)
{
    fprintf(stderr, "my_authenticate: user=%s group=%s\n",
	    user ? user : "none", group ? group : "none");
    // authentication handler
    if (!user && !group && !password)
	return YAZPROXY_RET_OK;   // OK if anonymous
    if (user && !strcmp(user, "guest")
	&& password && !strcmp(password, "guest"))  // or guest guest
	return YAZPROXY_RET_OK;
    return YAZPROXY_RET_PERM;  // fail otherwise
}

Yaz_ProxyModule_int0 interface0 = {
    my_init,
    my_destroy,
    my_authenticate
};

Yaz_ProxyModule_entry yazproxy_module = {
    0,                            // interface version
    "sample",                     // name
    "Sample Module for YAZ Proxy",// description
    &interface0
};
	
