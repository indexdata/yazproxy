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

#ifndef YAZ_PROXY_MODULE_H
#define YAZ_PROXY_MODULE_H

struct Yaz_ProxyModule_entry {
    int int_version;
    const char *module_name;
    const char *module_description;
    void *fl;
};

#define  YAZPROXY_RET_NOT_ME 0 /* Did not catch it. pass to other handler */
#define  YAZPROXY_RET_OK     1 /* OK, grabbed */
#define  YAZPROXY_RET_PERM   2 /* Permissiong denied, reject etc. */

struct Yaz_ProxyModule_int0 {
    void *(*init)(void);   // Init handler - returns module-specific handle

    void (*destroy)(       // Destroy handler
        void *handle       // module-specific handle as returned by init
        );

    int (*authenticate)(   // Authenticate handler. Returns YAZPROXY_RET_..
        void *handle,      // module-specific handle as returned by init
        const char *name,  // target name (or NULL if default target)
        void *element_ptr, // xmlnodePtr thing to XML config this
        const char *user,  // User ID (or NULL if no suppliied User ID)
        const char *group, // Group ID (or NULL if no supplied Group ID)
        const char *pw,    // Password (or NULL if no supplied password)
        const char *peer_IP// IP address of client
    );
};

class Yaz_ProxyModule;

class Yaz_ProxyModules {
    friend class Proxy_Msg;
 public:
    Yaz_ProxyModules();
    ~Yaz_ProxyModules();
    int authenticate(const char *module_name,
                     const char *target_name, void *element_ptr,
                     const char *user,
                     const char *group,
                     const char *password,
                     const char *peer_IP);
    int add_module(const char *fname);
    void unload_modules();
 private:
    Yaz_ProxyModule *m_list;
    int m_no_open;
};

#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

