/* $Id: yaz-bw.cpp,v 1.1.1.1 2004-04-11 11:36:46 adam Exp $
   Copyright (c) 1998-2004, Index Data.

This file is part of the yaz-proxy.

Zebra is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

Zebra is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with Zebra; see the file LICENSE.proxy.  If not, write to the
Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.
 */

#include <time.h>
#include <yaz/log.h>
#include <yaz++/proxy/bw.h>

Yaz_bw::Yaz_bw(int sz)
{
    m_sec = 0;
    m_size = sz;
    m_bucket = new int[m_size];
    m_ptr = 0;
}

Yaz_bw::~Yaz_bw()
{
    delete [] m_bucket;
}

int Yaz_bw::get_total()
{
    add_bytes(0);
    int bw = 0;
    int i;
    for (i = 0; i<m_size; i++)
	bw += m_bucket[i];
    return bw;
}

void Yaz_bw::add_bytes(int b)
{
    long now = time(0);

    int d = now - m_sec;
    if (d > m_size)
	d = m_size;
    while (--d >= 0)
    {
	if (++m_ptr == m_size)
	    m_ptr = 0;
	m_bucket[m_ptr] = 0;
    }
    m_bucket[m_ptr] += b;
    m_sec = now;
}

