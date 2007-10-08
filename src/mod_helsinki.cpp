/* $Id: mod_helsinki.cpp,v 1.4 2007-10-08 08:14:02 adam Exp $
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
#include <unistd.h>

#include <yazproxy/module.h>

#include <yaz/log.h>

#include <time.h>

#if YAZ_HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

struct IP_ADDRESS
{
    unsigned int a1, a2, a3, a4;
};

void *my_init(void)
{
    return 0;  // no private data for handler
}

void my_destroy(void *p)
{
    // private data destroy
}

void zero_address(IP_ADDRESS *addr)
{
    addr->a1 = addr->a2 = addr->a3 = addr->a4 = 0;
}

int str_to_address(const char *str, IP_ADDRESS *addr)
{
    zero_address(addr);
    return sscanf(str, "%3u.%3u.%3u.%3u", &addr->a1, &addr->a2, &addr->a3, &addr->a4);
}

void str_to_address_range(const char *str,
                          IP_ADDRESS *range_lo,
                          IP_ADDRESS *range_hi)
{
    char lo[16], hi[16];
    *lo = '\0';
    *hi = '\0';
    int num = sscanf(str, "%15[^-]-%15s", lo, hi);

    if (num == 1)
    {
        // Create a range from a single address or a part of it (e.g. 192.168)
        num = str_to_address(lo, range_lo);
        if (num == 1)
        {
            range_hi->a1 = range_lo->a1;
            range_hi->a2 = range_hi->a3 = range_hi->a4 = 255;
        }
        else if (num == 2)
        {
            range_hi->a1 = range_lo->a1;
            range_hi->a2 = range_lo->a2;
            range_hi->a3 = range_hi->a4 = 255;
        }
        else if (num == 3)
        {
            range_hi->a1 = range_lo->a1;
            range_hi->a2 = range_lo->a2;
            range_hi->a3 = range_lo->a3;
            range_hi->a4 = 255;
        }
        else
        {
            range_hi->a1 = range_lo->a1;
            range_hi->a2 = range_lo->a2;
            range_hi->a3 = range_lo->a3;
            range_hi->a4 = range_lo->a4;
        }
        return;
    }

    // If a range is specified, both ends need to be full addresses
    if (str_to_address(lo, range_lo) != 4 || str_to_address(hi, range_hi) != 4)
    {
        zero_address(range_lo);
        zero_address(range_hi);
    }
}

unsigned int address_to_int(IP_ADDRESS addr)
{
    return addr.a1 << 24 | addr.a2 << 16 | addr.a3 << 8 | addr.a4;
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
    // args holds args (or NULL if none are provided)

    yaz_log(YLOG_LOG, "Authentication: authenticating user %s, address %s", user ? user : "(none)", peer_IP ? peer_IP : "-");

    // authentication handler
    char user_file[255], ip_file[255];
    *user_file = '\0';
    *ip_file = '\0';
    sscanf(args, "%254[^:]:%254s", user_file, ip_file);

    yaz_log(YLOG_DEBUG, "Authentication: user file: %s, ip file: %s", user_file, ip_file);

    // Check if the IP address is listed in the file of allowed address ranges.
    // The format of the file:
    // 192.168.0
    // 192.168.0.100
    // 192.168.0.1-192.168.0.200
    int status = YAZPROXY_RET_PERM;
    if (ip_file && peer_IP)
    {
        yaz_log(YLOG_DEBUG, "Authentication: checking ip address");

        const char *pIP = peer_IP;
        if (strncmp(pIP, "tcp:", 4) == 0)
            pIP += 4;
        if (strncmp(pIP, "::ffff:", 7) == 0)
            pIP += 7;
        IP_ADDRESS peer_address;
        if (str_to_address(pIP, &peer_address) != 4)
            yaz_log(YLOG_WARN, "Authentication: could not decode peer IP address %s properly", pIP);
        unsigned int peer_address_int = address_to_int(peer_address);

        FILE *f = fopen(ip_file, "r");
        if (!f)
        {
            yaz_log(YLOG_WARN, "Authentication: could not open ip authentication file %s", ip_file);
                return YAZPROXY_RET_PERM;
        }
        while (!feof(f))
        {
            char line[255];
            *line = '\0';
            fgets(line, 254, f);
            line[254] = '\0';

            // Remove comments
            char *comment_pos = strchr(line, '#');
            if (comment_pos)
                *comment_pos = '\0';

            IP_ADDRESS range_lo, range_hi;
            str_to_address_range(line, &range_lo, &range_hi);
            if (address_to_int(range_lo) <= peer_address_int && peer_address_int <= address_to_int(range_hi))
            {
                status = YAZPROXY_RET_OK;
                break;
            }
        }
        fclose(f);
        if (status == YAZPROXY_RET_OK)
        {
            yaz_log(YLOG_LOG, "Authentication: IP address %s allowed", pIP);
            return YAZPROXY_RET_OK;
        }
    }

    if (!user || !password || !*user_file)
    {
        yaz_log(YLOG_LOG, "Authentication: anonymous authentication failed");
            return YAZPROXY_RET_PERM;
    }

    time_t current_time;
    time(&current_time);
    struct tm *local_time = localtime(&current_time);
    char current_date[10];
    sprintf(current_date, "%04d%02d%02d", local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday);

    FILE *f = fopen(user_file, "r");
    if (!f)
    {
        yaz_log(YLOG_WARN, "Authentication: could not open user authentication file %s", user_file);
            return YAZPROXY_RET_PERM;
    }
    while (!feof(f))
    {
        char line[255];
        *line = '\0';
        fgets(line, 254, f);
        line[254] = '\0';
        char *p = strchr(line, '\n');
        if (p) *p = '\0';

        char f_user[255], f_password[255], f_expiry[255];
        *f_user = '\0';
        *f_password = '\0';
        *f_expiry = '\0';
        sscanf(line, "%254[^:]:%254[^:]:%254s", f_user, f_password, f_expiry);

        if (strcmp(user, f_user) == 0 && strcmp(password, f_password) == 0 && (!*f_expiry || strcmp(current_date, f_expiry) <= 0))
        {
            status = YAZPROXY_RET_OK;
            break;
        }
    }
    fclose(f);
    yaz_log(YLOG_LOG, "Authentication: %s for user %s", status == YAZPROXY_RET_OK ? "successful" : "failed", user);
    return status;
}

Yaz_ProxyModule_int0 interface0 = {
    my_init,
    my_destroy,
    my_authenticate
};

Yaz_ProxyModule_entry yazproxy_module = {
    0,                            // interface version
    "helsinki",                     // name
    "Helsinki Module for YAZ Proxy",// description
    &interface0
};

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */
