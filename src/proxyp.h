/* $Id: proxyp.h,v 1.1 2004-12-03 14:28:18 adam Exp $
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

#if HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

#if HAVE_USEMARCON
#include <objectlist.h>
#endif

#include <yazproxy/proxy.h>

class Yaz_usemarcon {
 public:
    Yaz_usemarcon();
    ~Yaz_usemarcon();

    int convert(const char *stage1, const char *stage2,
		const char *input, int input_len,
		char **output, int *output_len);
#if HAVE_USEMARCON
    CDetails *m_stage1;
    CDetails *m_stage2;
#else
    int dummy;
#endif
};
