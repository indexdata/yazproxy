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

#include <time.h>
#include <yaz/log.h>
#include <yazproxy/bw.h>

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

/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

