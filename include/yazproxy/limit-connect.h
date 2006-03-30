/* $Id: limit-connect.h,v 1.1 2006-03-30 10:35:15 adam Exp $
   Copyright (c) 1998-2006, Index Data.

This file is part of the yazproxy.

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

#ifndef YAZPROXY_LIMIT_CONNECT_H
#define YAZPROXY_LIMIT_CONNECT_H

#include <yaz/yconfig.h>
#include <yazproxy/bw.h>

class LimitConnect {
public:
    LimitConnect();
    ~LimitConnect();
    void add_connect(const char *peername);
    int get_total(const char *peername);
    void cleanup(bool all);
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
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

