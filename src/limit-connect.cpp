/* $Id: limit-connect.cpp,v 1.1 2006-03-30 10:35:15 adam Exp $
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

#include <yazproxy/limit-connect.h>

#include <time.h>
#include <string.h>
#include <yaz/xmalloc.h>

struct LimitConnect::Peer {
    friend class LimitConnect;
    
    Peer(int sz, const char *peername);
    ~Peer();
    void add_connect();
    
    char *m_peername;
    Yaz_bw m_bw;
    Peer *m_next;
};

LimitConnect::LimitConnect()
{
    m_period = 60;
    m_peers = 0;
}

LimitConnect::~LimitConnect()
{
    cleanup(true);
}

LimitConnect::Peer::Peer(int sz, const char *peername) : m_bw(sz)
{
    m_peername = xstrdup(peername);
    m_next = 0;
}

LimitConnect::Peer::~Peer()
{
    xfree(m_peername);
}

void LimitConnect::Peer::add_connect()
{
    m_bw.add_bytes(1);
}

LimitConnect::Peer **LimitConnect::lookup(const char *peername)
{
    Peer **p = &m_peers;
    while (*p)
    {
	if (!strcmp((*p)->m_peername, peername))
	    break;
	p = &(*p)->m_next;
    }
    return p;
}

void LimitConnect::add_connect(const char *peername)
{
    Peer **p = lookup(peername);
    if (!*p)
	*p = new Peer(m_period, peername);
    (*p)->add_connect();
}

int LimitConnect::get_total(const char *peername)
{
    Peer **p = lookup(peername);
    if (!*p)
	return 0;
    return (*p)->m_bw.get_total();
}

void LimitConnect::cleanup(bool all)
{
    Peer **p = &m_peers;
    while (*p)
    {
	Peer *tp = *p;
	if (all || (tp->m_bw.get_total() == 0))
	{
	    *p = tp->m_next;
	    delete tp;
	}
	else
	    p = &tp->m_next;
    }
}

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */
