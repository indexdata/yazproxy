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

#ifndef YAZPROXY_YAZ_BW_H
#define YAZPROXY_YAZ_BW_H

#include <yaz/yconfig.h>

class YAZ_EXPORT Yaz_bw {
 public:
    Yaz_bw(int sz);
    ~Yaz_bw();
    void add_bytes(int m);
    int get_total();
 private:
    long m_sec;   // time of most recent bucket
    int *m_bucket;
    int m_ptr;
    int m_size;
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

