/* $Id: bw.h,v 1.3 2004-04-22 07:46:21 adam Exp $
   Copyright (c) 1998-2004, Index Data.

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

