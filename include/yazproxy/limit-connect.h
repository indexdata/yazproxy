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

#ifndef YAZPROXY_LIMIT_CONNECT_H
#define YAZPROXY_LIMIT_CONNECT_H

#include <yaz/yconfig.h>
#include <yazproxy/bw.h>

class YAZ_EXPORT LimitConnect {
public:
    LimitConnect();
    ~LimitConnect();
    void add_connect(const char *peername);
    int get_total(const char *peername);
    void cleanup(bool all);
    void set_period(int sec);
private:
    struct Peer;

    int m_period;
    Peer *m_peers;
    Peer **lookup(const char *peername);
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

