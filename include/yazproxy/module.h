/* $Id: module.h,v 1.1 2005-02-11 15:19:08 adam Exp $
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

#ifndef YAZ_PROXY_MODULE_H
#define YAZ_PROXY_MODULE_H_INCLUDED

struct Yaz_ProxyModule_entry {
    int int_version;
    char *module_name;
    char *module_description;
    void *fl;
};

#define  YAZPROXY_RET_NOT_ME 0 /* Did not catch it. pass to other handler */
#define  YAZPROXY_RET_OK     1 /* OK, grabbed */
#define  YAZPROXY_RET_PERM   2 /* Permissiong denied, reject etc. */

struct Yaz_ProxyModule_int0 {
    void *(*init)(void);
    void (*destroy)(void *handle);
    int (*authenticate)(void *handle,
			const char *user, const char *group, const char *pw);
};

#endif
