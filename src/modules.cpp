/* $Id: modules.cpp,v 1.5 2006-03-09 14:12:24 adam Exp $
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
#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <yaz/nmem.h>
#include <yaz/log.h>
#include <yazproxy/module.h>

class Yaz_ProxyModule {
    friend class Proxy_Msg;
private:
    void *m_dl_handle;                /* dlopen/close handle */
    Yaz_ProxyModule_entry *m_entry;
    Yaz_ProxyModule *m_next; 
    void *m_user_handle;              /* user handle */
public:
    Yaz_ProxyModule(void *dl_handle, Yaz_ProxyModule_entry *ent,
                    Yaz_ProxyModule *next);
    ~Yaz_ProxyModule();
    
    Yaz_ProxyModule *get_next() { return m_next; };
    int is_module(const char *name);
    int authenticate(const char *target_name, void *element_ptr,
                     const char *user, const char *group, const char *password,
                     const char *peer_IP);
};

int Yaz_ProxyModule::is_module(const char *name)
{
    if (!name || !strcmp(m_entry->module_name, name))
        return 1;
    return 0;
}

Yaz_ProxyModule::Yaz_ProxyModule(void *dl_handle, Yaz_ProxyModule_entry *ent,
                                 Yaz_ProxyModule *next)
{
    m_dl_handle = dl_handle;
    m_entry = ent;
    m_next = next;
    m_user_handle = 0;
    if (m_entry->int_version == 0)
    {
        struct Yaz_ProxyModule_int0 *int0 =
            reinterpret_cast<Yaz_ProxyModule_int0 *>(m_entry->fl);
        if (int0->init)
            m_user_handle = (*int0->init)();
    }
}

Yaz_ProxyModule::~Yaz_ProxyModule()
{
    if (m_entry->int_version == 0)
    {
        struct Yaz_ProxyModule_int0 *int0 =
            reinterpret_cast<Yaz_ProxyModule_int0 *>(m_entry->fl);
        if (int0->destroy)
            (*int0->destroy)(m_user_handle);
    }
#if HAVE_DLFCN_H
    dlclose(m_dl_handle);
#endif
}

int Yaz_ProxyModule::authenticate(const char *name,
                                  void *element_ptr,
                                  const char *user, const char *group,
                                  const char *password,
                                  const char *peer_IP)
{
    if (m_entry->int_version == 0)
    {
        struct Yaz_ProxyModule_int0 *int0 =
            reinterpret_cast<Yaz_ProxyModule_int0 *>(m_entry->fl);
        
        if (!int0->authenticate)
            return YAZPROXY_RET_NOT_ME;
        return (*int0->authenticate)(m_user_handle, name, element_ptr,
                                     user, group, password, peer_IP);
    }
    return YAZPROXY_RET_NOT_ME;
}

Yaz_ProxyModules::Yaz_ProxyModules()
{
    m_list = 0;
    m_no_open = 0;
}


Yaz_ProxyModules::~Yaz_ProxyModules()
{
    unload_modules();
}

void Yaz_ProxyModules::unload_modules()
{
    Yaz_ProxyModule *m = m_list;
    while (m)
    {
        Yaz_ProxyModule *m_next = m->get_next();
        delete m;
        m_no_open--;
        m = m_next;
    }
    m_list = 0;
}


int Yaz_ProxyModules::authenticate(const char *module_name,
                                   const char *target_name, void *element_ptr,
                                   const char *user,
                                   const char *group,
                                   const char *password,
                                   const char *peer_IP)
{
    int ret = YAZPROXY_RET_NOT_ME;
    Yaz_ProxyModule *m = m_list;
    for (; m; m = m->get_next())
    {
        if (m->is_module(module_name))
        {
            ret = m->authenticate(target_name, element_ptr,
                                  user, group, password,
                                  peer_IP);
            if (ret != YAZPROXY_RET_NOT_ME)
                break;
        }
    }
    return ret;
}

int Yaz_ProxyModules::add_module(const char *fname)
{
#if HAVE_DLFCN_H
    void *dl_handle = dlopen(fname, RTLD_NOW|RTLD_GLOBAL);
    if (dl_handle)
    {
        Yaz_ProxyModule_entry *fl_ptr = 0;
        fl_ptr = reinterpret_cast<Yaz_ProxyModule_entry *> 
            (dlsym(dl_handle, "yazproxy_module"));
        if (fl_ptr)
        {
            Yaz_ProxyModule *m = new Yaz_ProxyModule(dl_handle,
                                                     fl_ptr,
                                                     m_list);
            m_list = m;

            m_no_open++;
            yaz_log(YLOG_LOG, "Loaded module %s OK", fname);
            return 0;
        }
        else
        {
            yaz_log(YLOG_WARN, "Failed loading module %s - missing symbols",
                    fname);
            return -1;
            dlclose(dl_handle);
        }
    }
    else
    {
        yaz_log(YLOG_WARN, "Failed loading module %s", fname);
        return -1;
    }
#else
    yaz_log(YLOG_WARN, "Failed loading module %s - no module support", fname);
    return -1;
#endif
}

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

