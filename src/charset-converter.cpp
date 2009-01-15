/* This file is part of YAZ proxy
   Copyright (C) 1998-2009 Index Data

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

#include <yaz/log.h>
#include <yaz/proto.h>
#include "proxyp.h"

Yaz_CharsetConverter::Yaz_CharsetConverter()
{
    m_wrbuf = wrbuf_alloc();
    m_target_query_charset = 0;
    m_client_query_charset = 0;
    m_client_charset_selected = 0;
}

Yaz_CharsetConverter::~Yaz_CharsetConverter()
{
    wrbuf_destroy(m_wrbuf);
    xfree(m_target_query_charset);
    xfree(m_client_query_charset);
}

const char *Yaz_CharsetConverter::get_target_query_charset()
{
    return m_target_query_charset;
}

void Yaz_CharsetConverter::set_target_query_charset(const char *s)
{
    xfree(m_target_query_charset);
    m_target_query_charset = 0;
    if (s)
        m_target_query_charset = xstrdup(s);
}

void Yaz_CharsetConverter::set_client_query_charset(const char *s)
{
    xfree(m_client_query_charset);
    m_client_query_charset = 0;
    if (s)
        m_client_query_charset = xstrdup(s);
}

const char *Yaz_CharsetConverter::get_client_query_charset()
{
    return m_client_query_charset;
}

void Yaz_CharsetConverter::set_client_charset_selected(int sel)
{
    m_client_charset_selected = sel;
}

int Yaz_CharsetConverter::get_client_charset_selected()
{
    return m_client_charset_selected;
}

void Yaz_CharsetConverter::convert_type_1(char *buf_in, int len_in,
                                          char **buf_out, int *len_out,
                                          ODR o)
{
    wrbuf_rewind(m_wrbuf);
    wrbuf_iconv_write(m_wrbuf, m_ct, buf_in, len_in);
    wrbuf_iconv_reset(m_wrbuf, m_ct);

    *len_out = wrbuf_len(m_wrbuf);
    if (*len_out == 0)
    {   // we assume conversion failed
        *buf_out = buf_in;
        *len_out = len_in;
    }
    else
    {
        *buf_out = (char*) odr_malloc(o, *len_out);
        memcpy(*buf_out, wrbuf_buf(m_wrbuf), *len_out);
    }
}

void Yaz_CharsetConverter::convert_type_1(Z_Term *q, ODR o)
{
    switch(q->which)
    {
    case Z_Term_general:
        convert_type_1((char *) q->u.general->buf, q->u.general->len,
                       (char **) &q->u.general->buf, &q->u.general->len, o);
        break;
    }
}

void Yaz_CharsetConverter::convert_type_1(Z_Operand *q, ODR o)
{
    switch(q->which)
    {
    case Z_Operand_APT:
        convert_type_1(q->u.attributesPlusTerm->term, o);
        break;
    case Z_Operand_resultSetId:
        break;
    case Z_Operand_resultAttr:
        break;
    }
}

void Yaz_CharsetConverter::convert_type_1(Z_RPNStructure *q, ODR o)
{
    switch(q->which)
    {
    case Z_RPNStructure_simple:
        convert_type_1(q->u.simple, o);
        break;
    case Z_RPNStructure_complex:
        convert_type_1(q->u.complex->s1, o);
        convert_type_1(q->u.complex->s2, o);
        break;
    }
}

void Yaz_CharsetConverter::convert_type_1(Z_RPNQuery *q, ODR o)
{
    if (m_target_query_charset && m_client_query_charset)
    {
        m_ct = yaz_iconv_open(m_target_query_charset,
                              m_client_query_charset);
        if (m_ct)
        {
            convert_type_1(q->RPNStructure, o);
            yaz_iconv_close(m_ct);
        }
    }
}
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

