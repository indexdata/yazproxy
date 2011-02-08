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
#include "proxyp.h"

Yaz_usemarcon::Yaz_usemarcon()
{
#if HAVE_USEMARCON
    m_stage1 = 0;
    m_stage2 = 0;
#endif
}

Yaz_usemarcon::~Yaz_usemarcon()
{
#if HAVE_USEMARCON
    delete m_stage1;
    delete m_stage2;
#endif
}

int Yaz_usemarcon::convert(const char *stage1, const char *stage2,
                           const char *input, int input_len,
                           char **output, int *output_len)
{
#if HAVE_USEMARCON
    if (stage1 && *stage1)
    {
        char *converted;
        size_t convlen;
        if (!m_stage1)
        {
            m_stage1 = new Usemarcon();
        }
        m_stage1->SetIniFileName(stage1);
        m_stage1->SetMarcRecord((char*) input, input_len);
        int res = m_stage1->Convert();
        if (res == 0)
        {
            m_stage1->GetMarcRecord(converted, convlen);
            if (stage2 && *stage2)
            {
                if (!m_stage2)
                {
                    m_stage2 = new Usemarcon();
                }
                m_stage2->SetIniFileName(stage2);
                m_stage2->SetMarcRecord(converted, convlen);
                res = m_stage2->Convert();
                if (res == 0)
                {
                    free(converted);
                    m_stage2->GetMarcRecord(converted, convlen);
                }
                else
                {
                    yaz_log(YLOG_LOG, "USEMARCON stage 2 error %d", res);
                    return 0;
                }
            }
            *output = converted;
            *output_len = convlen;
            return 1;
        }
        else
        {
            yaz_log(YLOG_LOG, "USEMARCON stage 1 error %d", res);
        }
    }
#endif
    return 0;
}
/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

