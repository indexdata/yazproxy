/* This file is part of YAZ proxy
   Copyright (C) 1998-2011 Index Data

YAZ proxy is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

YAZ proxy is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <yazproxy/module.h>

#if YAZ_HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

void *my_init(void)
{
    return 0;  // no private data for handler
}

void my_destroy(void *p)
{
    // private data destroy
}

int my_authenticate(void *user_handle,
                    const char *target_name,
                    void *element_ptr,
                    const char *user, const char *group, const char *password,
                    const char *peer_IP)
{
    // see if we have an "args" attribute
    const char *args = 0;
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr = (xmlNodePtr) element_ptr;
    struct _xmlAttr *attr;
    
    for (attr = ptr->properties; attr; attr = attr->next)
    {
        if (!strcmp((const char *) attr->name, "args") &&
            attr->children && attr->children->type == XML_TEXT_NODE)
            args = (const char *) attr->children->content;
    }
#endif
    // args holds args (or NULL if  none is provided)

    sleep(2);
    fprintf(stderr, "my_authenticate: target=%s user=%s group=%s args=%s IP=%s"
            "\n",
            target_name ? target_name : "none", 
            user ? user : "none", group ? group : "none",
            args ? args : "none",
            peer_IP);
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
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

