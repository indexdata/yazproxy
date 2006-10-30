/* $Id: yaz-proxy.cpp,v 1.71 2006-10-30 14:24:18 adam Exp $
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

#ifdef WIN32
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>

#include <yaz/srw.h>
#include <yaz/marcdisp.h>
#include <yaz/yaz-iconv.h>
#include <yaz/log.h>
#include <yaz/diagbib1.h>
#include "proxyp.h"
#include <yaz/pquery.h>
#include <yaz/otherinfo.h>
#include <yaz/charneg.h>
#include "msg-thread.h"

using namespace yazpp_1;

#ifdef WIN32
#define strncasecmp _strnicmp
#endif

class YAZ_EXPORT Auth_Msg : public IMsg_Thread {
public:
    int m_ret;
    IMsg_Thread *handle();
    void result();
    Yaz_Proxy *m_proxy;
    NMEM m_nmem;
    char *m_apdu_buf;
    int m_apdu_len;
    Auth_Msg();
    virtual ~Auth_Msg();
};

Auth_Msg::Auth_Msg()
{
    m_nmem = nmem_create();
}

Auth_Msg::~Auth_Msg()
{
    nmem_destroy(m_nmem);
}

IMsg_Thread *Auth_Msg::handle()
{
    ODR decode = odr_createmem(ODR_DECODE);
    Z_APDU *apdu;

    odr_setbuf(decode, m_apdu_buf, m_apdu_len, 0);
    int r = z_APDU(decode, &apdu, 0, 0);
    if (!r)
    {
        yaz_log(YLOG_WARN, "decode failed in Auth_Msg::handle");
    }
    else
    {
        m_ret = m_proxy->handle_authentication(apdu);
    }
    odr_destroy(decode);
    return this;
}

void Auth_Msg::result()
{
    if (m_proxy->dec_ref())
    {
        yaz_log(YLOG_LOG, "Auth_Msg::proxy deleted meanwhile");
    }
    else
    {
        odr_setbuf(m_proxy->odr_decode(), m_apdu_buf, m_apdu_len, 0);
        Z_APDU *apdu = 0;
        int r = z_APDU(m_proxy->odr_decode(), &apdu, 0, 0);
        if (!r)
            yaz_log(YLOG_LOG, "Auth_Msg::result z_APDU failed");
        m_proxy->result_authentication(apdu, m_ret);
    }
    delete this;
}

void Yaz_Proxy::result_authentication(Z_APDU *apdu, int ret)
{
    if (apdu == 0 || ret == 0)
    {
        Z_APDU *apdu_reject = zget_APDU(odr_encode(), Z_APDU_initResponse);
        *apdu_reject->u.initResponse->result = 0;
        send_to_client(apdu_reject);
        dec_ref();
    }
    else
    {
        if (apdu->which == Z_APDU_initRequest)
        {
            Yaz_ProxyConfig *cfg = check_reconfigure();
            if (cfg)
                cfg->target_authentication(m_default_target, odr_encode(), 
                                           apdu->u.initRequest);
        }
        handle_incoming_Z_PDU_2(apdu);
    }
}

static const char *apdu_name(Z_APDU *apdu)
{
    switch (apdu->which)
    {
    case Z_APDU_initRequest:
        return "initRequest";
    case Z_APDU_initResponse:
        return "initResponse";
    case Z_APDU_searchRequest:
        return "searchRequest";
    case Z_APDU_searchResponse:
        return "searchResponse";
    case Z_APDU_presentRequest:
        return "presentRequest";
    case Z_APDU_presentResponse:
        return "presentResponse";
    case Z_APDU_deleteResultSetRequest:
        return "deleteResultSetRequest";
    case Z_APDU_deleteResultSetResponse:
        return "deleteResultSetResponse";
    case Z_APDU_scanRequest:
        return "scanRequest";
    case Z_APDU_scanResponse:
        return "scanResponse";
    case Z_APDU_sortRequest:
        return "sortRequest";
    case Z_APDU_sortResponse:
        return "sortResponse";
    case Z_APDU_extendedServicesRequest:
        return "extendedServicesRequest";
    case Z_APDU_extendedServicesResponse:
        return "extendedServicesResponse";
    case Z_APDU_close:
        return "close";
    }
    return "other";
}

static const char *gdu_name(Z_GDU *gdu)
{
    switch(gdu->which)
    {
    case Z_GDU_Z3950:
        return apdu_name(gdu->u.z3950);
    case Z_GDU_HTTP_Request:
        return "HTTP Request";
    case Z_GDU_HTTP_Response:
        return "HTTP Response";
    }
    return "Unknown request/response";
}

Yaz_Proxy::Yaz_Proxy(IPDU_Observable *the_PDU_Observable,
                     ISocketObservable *the_socket_observable,
                     Yaz_Proxy *parent)
    :
    Z_Assoc(the_PDU_Observable),
    m_bw_stat(60), m_pdu_stat(60), m_search_stat(60)
{
    m_PDU_Observable = the_PDU_Observable;
    m_socket_observable = the_socket_observable;
    m_client = 0;
    m_parent = parent;
    m_clientPool = 0;
    m_seqno = 1;
    m_keepalive_limit_bw = 500000;
    m_keepalive_limit_pdu = 1000;
    m_proxyTarget = 0;
    m_default_target = 0;
    m_proxy_negotiation_charset = 0;
    m_proxy_negotiation_lang = 0;
    m_proxy_negotiation_default_charset = 0;
    m_charset_converter = new Yaz_CharsetConverter;
    m_max_clients = 150;
    m_log_mask = 0;
    m_seed = time(0);
    m_client_idletime = 600;
    m_target_idletime = 600;
    m_optimize = xstrdup ("1");
    strcpy(m_session_str, "0 ");
    m_session_no = 0;
    m_bytes_sent = 0;
    m_bytes_recv = 0;
    m_bw_max = 0;
    m_pdu_max = 0;
    m_search_max = 0;
    m_max_connect = 0;
    m_max_connect_period = 0;
    m_limit_connect = 0;
    m_limit_connect_period = 0;
    m_timeout_mode = timeout_normal;
    m_timeout_gdu = 0;
    m_max_record_retrieve = 0;
    m_reconfig_flag = 0;
    m_config_fname = 0;
    m_request_no = 0;
    m_flag_invalid_session = 0;
    m_referenceId = 0;
    m_referenceId_mem = nmem_create();
    m_config = 0;
    m_marcxml_mode = none;
    m_stylesheet_xsp = 0;
    m_stylesheet_nprl = 0;
    m_stylesheet_apdu = 0;
    m_s2z_stylesheet = 0;
    m_s2z_database = 0;
    m_schema = 0;
    m_backend_type = 0;
    m_backend_charset = 0;
    m_frontend_type = 0;
    m_initRequest_apdu = 0;
    m_initRequest_mem = 0;
    m_initRequest_preferredMessageSize = 0;
    m_initRequest_maximumRecordSize = 0;
    m_initRequest_options = 0;
    m_initRequest_version = 0;
    m_initRequest_oi_negotiation_charsets = 0;
    m_initRequest_oi_negotiation_num_charsets = 0;
    m_initRequest_oi_negotiation_langs = 0;
    m_initRequest_oi_negotiation_num_langs = 0;
    m_initRequest_oi_negotiation_selected = 0;
    m_apdu_invalid_session = 0;
    m_mem_invalid_session = 0;
    m_s2z_odr_init = 0;
    m_s2z_odr_search = 0;
    m_s2z_init_apdu = 0;
    m_s2z_search_apdu = 0;
    m_s2z_present_apdu = 0;
    m_http_keepalive = 0;
    m_http_version = 0;
    m_soap_ns = 0;
    m_s2z_packing = Z_SRW_recordPacking_string;
#if HAVE_GETTIMEOFDAY
    m_time_tv = xmalloc(sizeof(struct timeval));
    struct timeval *tv = (struct timeval *) m_time_tv;
    tv->tv_sec = 0;
    tv->tv_usec = 0;
#else
    m_time_tv = 0;
#endif
    m_usemarcon_ini_stage1 = 0;
    m_usemarcon_ini_stage2 = 0;
    m_usemarcon = new Yaz_usemarcon();
    if (!m_parent)
        low_socket_open();
    m_my_thread = 0;
    m_ref_count = 1;
    m_main_ptr_dec = false;
    m_peername = 0;
    m_num_msg_threads = 0;
}

void Yaz_Proxy::inc_ref()
{
    m_ref_count++;
}

Yaz_Proxy::~Yaz_Proxy()
{
    yaz_log(YLOG_LOG, "%sClosed %d/%d sent/recv bytes total", m_session_str,
            m_bytes_sent, m_bytes_recv);
    nmem_destroy(m_initRequest_mem);
    nmem_destroy(m_mem_invalid_session);
    nmem_destroy(m_referenceId_mem);

    xfree(m_proxyTarget);
    xfree(m_default_target);
    xfree(m_proxy_negotiation_charset);
    xfree(m_proxy_negotiation_lang);
    xfree(m_proxy_negotiation_default_charset);
    delete m_charset_converter;
    xfree(m_optimize);

#if YAZ_HAVE_XSLT
    if (m_stylesheet_xsp)
        xsltFreeStylesheet((xsltStylesheetPtr) m_stylesheet_xsp);
#endif
    xfree (m_time_tv);

    xfree (m_peername);
    xfree (m_schema);
    xfree (m_backend_type);
    xfree (m_backend_charset);
    xfree (m_usemarcon_ini_stage1);
    xfree (m_usemarcon_ini_stage2);
    delete m_usemarcon;
    if (m_s2z_odr_init)
        odr_destroy(m_s2z_odr_init);
    if (m_s2z_odr_search)
        odr_destroy(m_s2z_odr_search);
    if (!m_parent)
        low_socket_close();
    if (!m_parent)
        delete m_my_thread;
    delete m_config;
}

void Yaz_Proxy::set_debug_mode(int mode)
{
    m_debug_mode = mode;
}

int Yaz_Proxy::set_config(const char *config)
{
    delete m_config;
    m_config = new Yaz_ProxyConfig();
    xfree(m_config_fname);
    m_config_fname = xstrdup(config);
    int r = m_config->read_xml(config);
    if (!r)
    {
        int period = 60;
        m_config->get_generic_info(&m_log_mask, &m_max_clients,
                                   &m_max_connect, &m_limit_connect, &period,
                                   &m_num_msg_threads);
        m_connect.set_period(period);
    }
    return r;
}

void Yaz_Proxy::set_default_target(const char *target)
{
    xfree (m_default_target);
    m_default_target = 0;
    if (target)
        m_default_target = (char *) xstrdup (target);
}

void Yaz_Proxy::set_proxy_negotiation (const char *charset, const char *lang,
                                       const char *default_charset)
{
    yaz_log(YLOG_DEBUG, "%sSet the proxy negotiation: charset to '%s', "
        "default charset to '%s', language to '%s'", m_session_str, 
        charset?charset:"none",
        default_charset?default_charset:"none",
        lang?lang:"none");
    xfree (m_proxy_negotiation_charset);
    xfree (m_proxy_negotiation_lang);
    m_proxy_negotiation_charset = m_proxy_negotiation_lang = 0;
    if (charset)
        m_proxy_negotiation_charset = (char *) xstrdup (charset);
    if (lang)
        m_proxy_negotiation_lang = (char *) xstrdup (lang);
    if (default_charset)
        m_proxy_negotiation_default_charset =
            (char *) xstrdup (default_charset);
}

Yaz_ProxyConfig *Yaz_Proxy::check_reconfigure()
{
    if (m_parent)
        return m_parent->check_reconfigure();

    Yaz_ProxyConfig *cfg = m_config;
    if (m_reconfig_flag)
    {
        yaz_log(YLOG_LOG, "reconfigure");
        yaz_log_reopen();
        if (m_config_fname && cfg)
        {
            yaz_log(YLOG_LOG, "reconfigure config %s", m_config_fname);
            int r = cfg->read_xml(m_config_fname);
            if (r)
                yaz_log(YLOG_WARN, "reconfigure failed");
            else
            {
                m_log_mask = 0;
                int period = 60;
                cfg->get_generic_info(&m_log_mask, &m_max_clients,
                                      &m_max_connect, &m_limit_connect,
                                      &period, &m_num_msg_threads);
                m_connect.set_period(period);
            }
        }
        else
            yaz_log(YLOG_LOG, "reconfigure");
        m_reconfig_flag = 0;
    }
    return cfg;
}

IPDU_Observer *Yaz_Proxy::sessionNotify(IPDU_Observable
                                        *the_PDU_Observable, int fd)
{
    check_reconfigure();

    char session_str[200];
    const char *peername = the_PDU_Observable->getpeername();
    if (!peername)
        peername = "nullpeer";

    if (m_log_mask & PROXY_LOG_IP_CLIENT)
        sprintf(session_str, "%ld:%d %.80s %d ",
                (long) time(0), m_session_no, peername, 0);
    else
        sprintf(session_str, "%ld:%d %d ",
                (long) time(0), m_session_no, 0);
    m_session_no++;

    yaz_log (YLOG_LOG, "%sNew session %s", session_str, peername);

    Yaz_Proxy *new_proxy = new Yaz_Proxy(the_PDU_Observable,
                                         m_socket_observable, this);

    new_proxy->m_config = 0;
    new_proxy->m_config_fname = 0;
    new_proxy->timeout(m_client_idletime);
    new_proxy->m_target_idletime = m_target_idletime;
    new_proxy->set_default_target(m_default_target);
    new_proxy->m_max_clients = m_max_clients;
    new_proxy->m_log_mask = m_log_mask;
    new_proxy->m_session_no = m_session_no;
    new_proxy->m_num_msg_threads = m_num_msg_threads;

#if 0
    // in case we want to watch a particular client..
    if (!strcmp(peername, "tcp:163.121.19.82")) // NIS GROUP
        new_proxy->m_log_mask = 255;
#endif

    new_proxy->set_APDU_log(get_APDU_log());
    if (new_proxy->m_log_mask & PROXY_LOG_APDU_CLIENT)
        new_proxy->set_APDU_yazlog(1);
    else
        new_proxy->set_APDU_yazlog(0);
    strcpy(new_proxy->m_session_str, session_str);
    new_proxy->m_peername = xstrdup(peername);
    new_proxy->set_proxy_negotiation(m_proxy_negotiation_charset,
        m_proxy_negotiation_lang, m_proxy_negotiation_default_charset);
    // create thread object the first time we get an incoming connection
    if (!m_my_thread && m_num_msg_threads > 0)
    {
        yaz_log (YLOG_LOG, "%sStarting message thread management. number=%d",
                 session_str, m_num_msg_threads);
        m_my_thread = new Msg_Thread(m_socket_observable, m_num_msg_threads);
    }
    new_proxy->m_my_thread = m_my_thread;
    return new_proxy;
}

char *Yaz_Proxy::get_cookie(Z_OtherInformation **otherInfo)
{
    int oid[OID_SIZE];
    Z_OtherInformationUnit *oi;
    struct oident ent;
    ent.proto = PROTO_Z3950;
    ent.oclass = CLASS_USERINFO;
    ent.value = (oid_value) VAL_COOKIE;
    assert (oid_ent_to_oid (&ent, oid));

    if (oid_ent_to_oid (&ent, oid) &&
        (oi = update_otherInformation(otherInfo, 0, oid, 1, 1)) &&
        oi->which == Z_OtherInfo_characterInfo)
        return oi->information.characterInfo;
    return 0;
}
char *Yaz_Proxy::get_proxy(Z_OtherInformation **otherInfo)
{
    int oid[OID_SIZE];
    Z_OtherInformationUnit *oi;
    struct oident ent;
    ent.proto = PROTO_Z3950;
    ent.oclass = CLASS_USERINFO;
    ent.value = (oid_value) VAL_PROXY;
    if (oid_ent_to_oid (&ent, oid) &&
        (oi = update_otherInformation(otherInfo, 0, oid, 1, 1)) &&
        oi->which == Z_OtherInfo_characterInfo)
        return oi->information.characterInfo;
    return 0;
}
const char *Yaz_Proxy::load_balance(const char **url)
{
    int zurl_in_use[MAX_ZURL_PLEX];
    int zurl_in_spare[MAX_ZURL_PLEX];
    Yaz_ProxyClient *c;
    int i;

    for (i = 0; i<MAX_ZURL_PLEX; i++)
    {
        zurl_in_use[i] = 0;
        zurl_in_spare[i] = 0;
    }
    for (c = m_parent->m_clientPool; c; c = c->m_next)
    {
        for (i = 0; url[i]; i++)
            if (!strcmp(url[i], c->get_hostname()))
            {
                zurl_in_use[i]++;
                if (c->m_cookie == 0 && c->m_server == 0 && c->m_waiting == 0)
                    zurl_in_spare[i]++;
            }
    }
    int min_use = 100000;
    int spare_for_min = 0;
    int max_spare = 0;
    const char *ret_min = 0;
    const char *ret_spare = 0;
    for (i = 0; url[i]; i++)
    {
        yaz_log(YLOG_DEBUG, "%szurl=%s use=%d spare=%d",
                m_session_str, url[i], zurl_in_use[i], zurl_in_spare[i]);
        if (min_use > zurl_in_use[i])
        {
            ret_min = url[i];
            min_use = zurl_in_use[i];
            spare_for_min = zurl_in_spare[i];
        }
        if (max_spare < zurl_in_spare[i])
        {
            ret_spare = url[i];
            max_spare = zurl_in_spare[i];
        }
    }
    return ret_min;
}

Yaz_ProxyClient *Yaz_Proxy::get_client(Z_APDU *apdu, const char *cookie,
                                       const char *proxy_host)
{
    assert (m_parent);
    Yaz_Proxy *parent = m_parent;
    Yaz_ProxyClient *c = m_client;

    if (!m_proxyTarget)
    {
        const char *url[MAX_ZURL_PLEX];
        Yaz_ProxyConfig *cfg = check_reconfigure();
        if (proxy_host)
        {
            if (parent && parent->m_debug_mode)
            {
                // only to be enabled for debugging...
                if (!strcmp(proxy_host, "stop"))
                    exit(0);
            }
            xfree(m_default_target);
            m_default_target = xstrdup(proxy_host);
        }
        proxy_host = m_default_target;
        int client_idletime = -1;
        const char *cql2rpn_fname = 0;
        const char *negotiation_charset = 0;
        const char *negotiation_lang = 0;
        const char *query_charset = 0;
        const char *default_client_query_charset = 0;
        url[0] = m_default_target;
        url[1] = 0;
        if (cfg)
        {
            int pre_init = 0;
            cfg->get_target_info(proxy_host, url, &m_bw_max,
                                 &m_pdu_max, &m_max_record_retrieve,
                                 &m_search_max,
                                 &m_target_idletime, &client_idletime,
                                 &parent->m_max_clients,
                                 &m_keepalive_limit_bw,
                                 &m_keepalive_limit_pdu,
                                 &pre_init,
                                 &cql2rpn_fname,
                                 &negotiation_charset,
                                 &negotiation_lang,
                                 &query_charset,
                                 &default_client_query_charset);
        }
        if (client_idletime != -1)
        {
            m_client_idletime = client_idletime;
            timeout(m_client_idletime);
        }

        // get those FILE descriptors available 
        m_parent->low_socket_close();
        if (cql2rpn_fname)
            m_cql2rpn.set_pqf_file(cql2rpn_fname);
        // reserve them again
        m_parent->low_socket_open();
        
        if (negotiation_charset || negotiation_lang || default_client_query_charset)
        {
            set_proxy_negotiation(negotiation_charset,
                negotiation_lang, default_client_query_charset);
        }
        m_charset_converter->set_target_query_charset(query_charset);
        if (!url[0])
        {
            yaz_log(YLOG_LOG, "%sNo default target", m_session_str);
            return 0;
        }
        // we don't handle multiplexing for cookie session, so we just
        // pick the first one in this case (anonymous users will be able
        // to use any backend)
        if (cookie && *cookie)
            m_proxyTarget = (char*) xstrdup(url[0]);
        else
            m_proxyTarget = (char*) xstrdup(load_balance(url));
    }
    if (cookie && *cookie)
    {   // search in sessions with a cookie
        for (c = parent->m_clientPool; c; c = c->m_next)
        {
            assert (c->m_prev);
            assert (*c->m_prev == c);
            if (c->m_cookie && !strcmp(cookie,c->m_cookie) &&
                !strcmp(m_proxyTarget, c->get_hostname()))
            {
                // Found it in cache
                // The following handles "cancel"
                // If connection is busy (waiting for PDU) and
                // we have an initRequest we can safely do re-open
                if (c->m_waiting && apdu->which == Z_APDU_initRequest)
                {
                    yaz_log (YLOG_LOG, "%s REOPEN target=%s", m_session_str,
                             c->get_hostname());
                    c->close();
                    c->m_init_flag = 0;

                    c->m_last_ok = 0;
                    c->m_cache.clear();
                    c->m_last_resultCount = 0;
                    c->m_sr_transform = 0;
                    c->m_waiting = 0;
                    c->m_resultSetStartPoint = 0;
                    c->m_target_idletime = m_target_idletime;
                    if (c->client(m_proxyTarget))
                    {
                        delete c;
                        return 0;
                    }
                    c->timeout(30);
                }
                c->m_seqno = parent->m_seqno;
                if (c->m_server && c->m_server != this)
                    c->m_server->m_client = 0;
                c->m_server = this;
                (parent->m_seqno)++;
                yaz_log (YLOG_DEBUG, "get_client 1 %p %p", this, c);
                return c;
            }
        }
    }
    else if (!c && apdu->which == Z_APDU_initRequest )
    {
        // anonymous sessions without cookie.
        // if authentication is set it is NOT anonymous se we can't share them.
        // If charset and lang negotiation is use it is NOT anonymous session too.
        for (c = parent->m_clientPool; c; c = c->m_next)
        {
            assert(c->m_prev);
            assert(*c->m_prev == c);
            if (c->m_server == 0 && c->m_cookie == 0 &&  c->m_waiting == 0 
                && c->compare_idAuthentication(apdu)
                && c->compare_charset(apdu)
                && !strcmp(m_proxyTarget, c->get_hostname()))
            {
                // found it in cache
                yaz_log (YLOG_LOG, "%sREUSE %d %s",
                         m_session_str, parent->m_seqno, c->get_hostname());
                
                c->m_seqno = parent->m_seqno;
                assert(c->m_server == 0);
                c->m_server = this;

                if (parent->m_log_mask & PROXY_LOG_APDU_SERVER)
                    c->set_APDU_yazlog(1);
                else
                    c->set_APDU_yazlog(0);

                (parent->m_seqno)++;

                parent->pre_init();

                return c;
            }
        }
    }
    if (!m_client)
    {
        if (apdu->which != Z_APDU_initRequest)
        {
            yaz_log (YLOG_LOG, "%sno init request as first PDU", m_session_str);
            return 0;
        }
        // go through list of clients - and find the lowest/oldest one.
        Yaz_ProxyClient *c_min = 0;
        int min_seq = -1;
        int no_of_clients = 0;
        if (parent->m_clientPool)
            yaz_log (YLOG_DEBUG, "Existing sessions");
        for (c = parent->m_clientPool; c; c = c->m_next)
        {
            yaz_log (YLOG_DEBUG, " Session %-3d wait=%d %s cookie=%s", c->m_seqno,
                               c->m_waiting, c->get_hostname(),
                               c->m_cookie ? c->m_cookie : "");
            no_of_clients++;
            if (min_seq < 0 || c->m_seqno < min_seq)
            {
                min_seq = c->m_seqno;
                c_min = c;
            }
        }
        if (no_of_clients >= parent->m_max_clients)
        {
            c = c_min;
            if (c->m_waiting || strcmp(m_proxyTarget, c->get_hostname()))
            {
                yaz_log (YLOG_LOG, "%sMAXCLIENTS %d Destroy %d",
                         m_session_str, parent->m_max_clients, c->m_seqno);
                if (c->m_server && c->m_server != this)
                    c->m_server->dec_ref();
            }
            else
            {
                yaz_log (YLOG_LOG, "%sMAXCLIENTS %d Reuse %d %d %s",
                         m_session_str, parent->m_max_clients,
                         c->m_seqno, parent->m_seqno, c->get_hostname());
                xfree (c->m_cookie);
                c->m_cookie = 0;
                if (cookie)
                    c->m_cookie = xstrdup(cookie);
                c->m_seqno = parent->m_seqno;
                if (c->m_server && c->m_server != this)
                {
                    c->m_server->m_client = 0;
                    c->m_server->dec_ref();
                }
                (parent->m_seqno)++;
                c->m_target_idletime = m_target_idletime;
                c->timeout(m_target_idletime);

                if (parent->m_log_mask & PROXY_LOG_APDU_SERVER)
                    c->set_APDU_yazlog(1);
                else
                    c->set_APDU_yazlog(0);

                return c;
            }
        }
        else
        {
            yaz_log (YLOG_LOG, "%sNEW %d %s",
                     m_session_str, parent->m_seqno, m_proxyTarget);
            c = new Yaz_ProxyClient(m_PDU_Observable->clone(), parent);
            c->m_next = parent->m_clientPool;
            if (c->m_next)
                c->m_next->m_prev = &c->m_next;
            parent->m_clientPool = c;
            c->m_prev = &parent->m_clientPool;
        }

        xfree (c->m_cookie);
        c->m_cookie = 0;
        if (cookie)
            c->m_cookie = xstrdup(cookie);

        c->m_seqno = parent->m_seqno;
        c->m_init_flag = 0;
        c->m_last_resultCount = 0;
        c->m_last_ok = 0;
        c->m_cache.clear();
        c->m_sr_transform = 0;
        c->m_waiting = 0;
        c->m_resultSetStartPoint = 0;
        (parent->m_seqno)++;
        if (c->client(m_proxyTarget))
        {
            delete c;
            return 0;
        }
        c->m_target_idletime = m_target_idletime;
        c->timeout(30);

        if (parent->m_log_mask & PROXY_LOG_APDU_SERVER)
            c->set_APDU_yazlog(1);
        else
            c->set_APDU_yazlog(0);

        c->set_idAuthentication(apdu);
    }
    yaz_log (YLOG_DEBUG, "get_client 3 %p %p", this, c);
    return c;
}

void Yaz_Proxy::display_diagrecs(Z_DiagRec **pp, int num)
{
    int i;
    for (i = 0; i<num; i++)
    {
        oident *ent;
        Z_DefaultDiagFormat *r;
        Z_DiagRec *p = pp[i];
        if (p->which != Z_DiagRec_defaultFormat)
        {
            yaz_log(YLOG_LOG, "%sError no diagnostics", m_session_str);
            return;
        }
        else
            r = p->u.defaultFormat;
        if (!(ent = oid_getentbyoid(r->diagnosticSetId)) ||
            ent->oclass != CLASS_DIAGSET || ent->value != VAL_BIB1)
            yaz_log(YLOG_LOG, "%sError unknown diagnostic set", m_session_str);
        switch (r->which)
        {
        case Z_DefaultDiagFormat_v2Addinfo:
            yaz_log(YLOG_LOG, "%sError %d %s:%s",
                    m_session_str,
                    *r->condition, diagbib1_str(*r->condition),
                    r->u.v2Addinfo);
            break;
        case Z_DefaultDiagFormat_v3Addinfo:
            yaz_log(YLOG_LOG, "%sError %d %s:%s",
                    m_session_str,
                    *r->condition, diagbib1_str(*r->condition),
                    r->u.v3Addinfo);
            break;
        }
    }
}

int Yaz_Proxy::convert_xsl(Z_NamePlusRecordList *p, Z_APDU *apdu)
{
    if (!m_stylesheet_xsp || p->num_records <= 0)
    {
        return 0;  /* no XSLT to be done ... */
    }

    m_stylesheet_offset = 0;
    m_stylesheet_nprl = p;
    m_stylesheet_apdu = apdu;
    m_timeout_mode = timeout_xsl;

    timeout(0);
    return 1;
}

void Yaz_Proxy::convert_xsl_delay()
{
#if YAZ_HAVE_XSLT
    Z_NamePlusRecord *npr = m_stylesheet_nprl->records[m_stylesheet_offset];
    if (npr->which == Z_NamePlusRecord_databaseRecord)
    {
        Z_External *r = npr->u.databaseRecord;
        if (r->which == Z_External_octet)
        {
#if 0
            fwrite((char*) r->u.octet_aligned->buf, 1, r->u.octet_aligned->len, stdout);
#endif
            xmlDocPtr res, doc = xmlParseMemory(
                (char*) r->u.octet_aligned->buf,
                r->u.octet_aligned->len);


            yaz_log(YLOG_LOG, "%sXSLT convert %d",
                    m_session_str, m_stylesheet_offset);
            res = xsltApplyStylesheet((xsltStylesheetPtr) m_stylesheet_xsp,
                                      doc, 0);

            if (res)
            {
                xmlChar *out_buf;
                int out_len;
                xmlDocDumpFormatMemory (res, &out_buf, &out_len, 1);

                m_stylesheet_nprl->records[m_stylesheet_offset]->
                    u.databaseRecord =
                    z_ext_record(odr_encode(), VAL_TEXT_XML,
                                 (char*) out_buf, out_len);
                xmlFree(out_buf);
                xmlFreeDoc(res);
            }

            xmlFreeDoc(doc);
        }
    }
#endif
    m_stylesheet_offset++;
    if (m_stylesheet_offset == m_stylesheet_nprl->num_records)
    {
        m_timeout_mode = timeout_normal;
        m_stylesheet_nprl = 0;
#if YAZ_HAVE_XSLT
        if (m_stylesheet_xsp)
            xsltFreeStylesheet((xsltStylesheetPtr) m_stylesheet_xsp);
#endif
        m_stylesheet_xsp = 0;
        timeout(m_client_idletime);
        send_PDU_convert(m_stylesheet_apdu);
    }
    else
        timeout(0);
}

void Yaz_Proxy::convert_to_frontend_type(Z_NamePlusRecordList *p)
{
    if (m_frontend_type != VAL_NONE)
    {
        int i;
        for (i = 0; i < p->num_records; i++)
        {
            Z_NamePlusRecord *npr = p->records[i];
            if (npr->which == Z_NamePlusRecord_databaseRecord)
            {
                Z_External *r = npr->u.databaseRecord;
                if (r->which == Z_External_octet)
                {
#if HAVE_USEMARCON
                    if (m_usemarcon_ini_stage1 && *m_usemarcon_ini_stage1)
                    {
                        if (!m_usemarcon->m_stage1)
                        {
                            m_usemarcon->m_stage1 = new CDetails();
                        }
                        m_usemarcon->m_stage1->SetIniFileName(m_usemarcon_ini_stage1);
                        m_usemarcon->m_stage1->SetMarcRecord((char*) r->u.octet_aligned->buf, r->u.octet_aligned->len);
                        int res = m_usemarcon->m_stage1->Start();
                        if (res == 0)
                        {
                            char *converted;
                            int convlen;
                            m_usemarcon->m_stage1->GetMarcRecord(converted, convlen);
                            if (m_usemarcon_ini_stage2 && *m_usemarcon_ini_stage2)
                            {
                                if (!m_usemarcon->m_stage2)
                                {
                                    m_usemarcon->m_stage2 = new CDetails();
                                }
                                m_usemarcon->m_stage2->SetIniFileName(m_usemarcon_ini_stage2);
                                m_usemarcon->m_stage2->SetMarcRecord(converted, convlen);
                                res = m_usemarcon->m_stage2->Start();
                                if (res == 0)
                                {
                                    free(converted);
                                    m_usemarcon->m_stage2->GetMarcRecord(converted, convlen);
                                }
                                else
                                {
                                    yaz_log(YLOG_LOG, "%sUSEMARCON stage 2 error %d", m_session_str, res);
                                }
                            }
                            npr->u.databaseRecord =
                                z_ext_record(odr_encode(),
                                             m_frontend_type,
                                             converted,
                                             strlen(converted));
                            free(converted);
                        }
                        else
                        {
                            yaz_log(YLOG_LOG, "%sUSEMARCON stage 1 error %d", m_session_str, res);
                        }
                        continue;
                    }
#endif
/* HAVE_USEMARCON */
                    npr->u.databaseRecord =
                        z_ext_record(odr_encode(),
                                     m_frontend_type,
                                     (char*) r->u.octet_aligned->buf,
                                     r->u.octet_aligned->len);
                }
            }
        }
    }
}

void Yaz_Proxy::convert_records_charset(Z_NamePlusRecordList *p,
                                        const char *backend_charset)
{
    int sel =   m_charset_converter->get_client_charset_selected();
    const char *client_record_charset =
        m_charset_converter->get_client_query_charset();
    if (sel && backend_charset && client_record_charset &&
        strcmp(backend_charset, client_record_charset))
    {
        int i;
        yaz_iconv_t cd = yaz_iconv_open(client_record_charset,
                                        backend_charset);
        yaz_marc_t mt = yaz_marc_create();
        yaz_marc_xml(mt, YAZ_MARC_ISO2709);
        yaz_marc_iconv(mt, cd);
        for (i = 0; i < p->num_records; i++)
        {
            Z_NamePlusRecord *npr = p->records[i];
            if (npr->which == Z_NamePlusRecord_databaseRecord)
            {
                Z_External *r = npr->u.databaseRecord;
                oident *ent = oid_getentbyoid(r->direct_reference);
                if (!ent || ent->value == VAL_NONE)
                    continue;

                if (ent->value == VAL_SUTRS)
                {
                    WRBUF w = wrbuf_alloc();

                    wrbuf_iconv_write(w, cd,  (char*) r->u.octet_aligned->buf,
                                      r->u.octet_aligned->len);
                    npr->u.databaseRecord =
                        z_ext_record(odr_encode(), ent->value, wrbuf_buf(w),
                                     wrbuf_len(w));
                    wrbuf_free(w, 1);
                }
                else if (ent->value == VAL_TEXT_XML)
                {
                    ;
                }
                else if (r->which == Z_External_octet)
                {
                    int rlen;
                    char *result;
                    if (yaz_marc_decode_buf(mt,
                                            (char*) r->u.octet_aligned->buf,
                                            r->u.octet_aligned->len,
                                            &result, &rlen))
                    {
                        npr->u.databaseRecord =
                            z_ext_record(odr_encode(), ent->value, result, rlen);
                        yaz_log(YLOG_LOG, "%sRecoding MARC record",
                                m_session_str);
                    }
                }
            }
        }
        if (cd)
            yaz_iconv_close(cd);
        yaz_marc_destroy(mt);
    }
}

void Yaz_Proxy::convert_to_marcxml(Z_NamePlusRecordList *p,
                                   const char *backend_charset)
{
    int i;
    if (!backend_charset)
        backend_charset = "MARC-8";
    yaz_iconv_t cd = yaz_iconv_open("UTF-8", backend_charset);
    yaz_marc_t mt = yaz_marc_create();
    yaz_marc_xml(mt, YAZ_MARC_MARCXML);
    yaz_marc_iconv(mt, cd);
    for (i = 0; i < p->num_records; i++)
    {
        Z_NamePlusRecord *npr = p->records[i];
        if (npr->which == Z_NamePlusRecord_databaseRecord)
        {
            Z_External *r = npr->u.databaseRecord;
            if (r->which == Z_External_OPAC)
            {
                WRBUF w = wrbuf_alloc();

                yaz_opac_decode_wrbuf(mt, r->u.opac, w);
                npr->u.databaseRecord = z_ext_record(
                    odr_encode(), VAL_TEXT_XML,
                    wrbuf_buf(w), wrbuf_len(w)
                    );
                wrbuf_free(w, 1);
            }
            else if (r->which == Z_External_octet)
            {
                int rlen;
                char *result;
                if (yaz_marc_decode_buf(mt, (char*) r->u.octet_aligned->buf,
                                        r->u.octet_aligned->len,
                                        &result, &rlen))
                {
                    npr->u.databaseRecord =
                        z_ext_record(odr_encode(), VAL_TEXT_XML, result, rlen);
                }
            }
        }
    }
    if (cd)
        yaz_iconv_close(cd);
    yaz_marc_destroy(mt);
}

void Yaz_Proxy::logtime()
{
#if HAVE_GETTIMEOFDAY
    struct timeval *tv = (struct timeval*) m_time_tv;
    if (tv->tv_sec)
    {
        struct timeval tv1;
        gettimeofday(&tv1, 0);
        long diff = (tv1.tv_sec - tv->tv_sec)*1000000 +
            (tv1.tv_usec - tv->tv_usec);
        if (diff >= 0)
            yaz_log(YLOG_LOG, "%sElapsed %ld.%03ld", m_session_str,
                    diff/1000000, (diff/1000)%1000);
    }
    tv->tv_sec = 0;
    tv->tv_usec = 0;
#endif
}

int Yaz_Proxy::send_http_response(int code)
{
    ODR o = odr_encode();
    Z_GDU *gdu = z_get_HTTP_Response(o, code);
    Z_HTTP_Response *hres = gdu->u.HTTP_Response;
    if (m_http_version)
        hres->version = odr_strdup(o, m_http_version);
    if (m_http_keepalive)
        z_HTTP_header_add(o, &hres->headers, "Connection", "Keep-Alive");
    else
        timeout(0);
    if (code == 401)
        z_HTTP_header_add(o, &hres->headers, "WWW-Authenticate", 
                          "Basic realm=\"YAZ Proxy\"");


    if (m_log_mask & PROXY_LOG_REQ_CLIENT)
    {
        yaz_log (YLOG_LOG, "%sSending %s to client", m_session_str,
                 gdu_name(gdu));
    }
    int len;
    int r = send_GDU(gdu, &len);
    m_bytes_sent += len;
    m_bw_stat.add_bytes(len);
    logtime();

    recv_GDU_more(true);

    return r;
}

int Yaz_Proxy::send_srw_response(Z_SRW_PDU *srw_pdu, int http_code /* = 200 */)
{
    ODR o = odr_encode();
    const char *ctype = "text/xml";
    Z_GDU *gdu = z_get_HTTP_Response(o, http_code);
    Z_HTTP_Response *hres = gdu->u.HTTP_Response;
    if (m_http_version)
        hres->version = odr_strdup(o, m_http_version);
    z_HTTP_header_add(o, &hres->headers, "Content-Type", ctype);
    if (m_http_keepalive)
        z_HTTP_header_add(o, &hres->headers, "Connection", "Keep-Alive");
    else
        timeout(0);
    if (http_code == 401)
        z_HTTP_header_add(o, &hres->headers, "WWW-Authenticate", "Basic realm=\"YAZ Proxy\"");

    static Z_SOAP_Handler soap_handlers[2] = {
#if YAZ_HAVE_XSLT
        {"http://www.loc.gov/zing/srw/", 0,
         (Z_SOAP_fun) yaz_srw_codec},
#endif
        {0, 0, 0}
    };

    Z_SOAP *soap_package = (Z_SOAP*) odr_malloc(o, sizeof(Z_SOAP));
    soap_package->which = Z_SOAP_generic;
    soap_package->u.generic =
        (Z_SOAP_Generic *) odr_malloc(o,  sizeof(*soap_package->u.generic));
    soap_package->u.generic->no = 0;
    soap_package->u.generic->ns = soap_handlers[0].ns;
    soap_package->u.generic->p = (void *) srw_pdu;
    soap_package->ns = m_soap_ns;
    z_soap_codec_enc_xsl(o, &soap_package,
                         &hres->content_buf, &hres->content_len,
                         soap_handlers, 0, m_s2z_stylesheet);
    if (m_log_mask & PROXY_LOG_REQ_CLIENT)
    {
        yaz_log (YLOG_LOG, "%sSending %s to client", m_session_str,
                 gdu_name(gdu));
    }
    int len;
    int r = send_GDU(gdu, &len);
    m_bytes_sent += len;
    m_bw_stat.add_bytes(len);
    logtime();

    recv_GDU_more(true);

    return r;
}

int Yaz_Proxy::send_to_srw_client_error(int srw_error, const char *add)
{
    ODR o = odr_encode();
    Z_SRW_diagnostic *diagnostic = (Z_SRW_diagnostic *)
        odr_malloc(o, sizeof(*diagnostic));
    int num_diagnostic = 1;
    yaz_mk_std_diagnostic(o, diagnostic, srw_error, add);
    return send_srw_search_response(diagnostic, num_diagnostic, srw_error == 3 ? 401 : 200);
}

int Yaz_Proxy::z_to_srw_diag(ODR o, Z_SRW_searchRetrieveResponse *srw_res,
                             Z_DefaultDiagFormat *ddf)
{
    int bib1_code = *ddf->condition;
    if (bib1_code == 109)
        return 404;
    srw_res->num_diagnostics = 1;
    srw_res->diagnostics = (Z_SRW_diagnostic *)
        odr_malloc(o, sizeof(*srw_res->diagnostics));
    yaz_mk_std_diagnostic(o, srw_res->diagnostics,
                          yaz_diag_bib1_to_srw(*ddf->condition),
                          ddf->u.v2Addinfo);
    return 0;
}

int Yaz_Proxy::send_to_srw_client_ok(int hits, Z_Records *records, int start)
{
    ODR o = odr_encode();
    Z_SRW_PDU *srw_pdu = yaz_srw_get(o, Z_SRW_searchRetrieve_response);
    Z_SRW_searchRetrieveResponse *srw_res = srw_pdu->u.response;

    srw_res->numberOfRecords = odr_intdup (o, hits);
    if (records && records->which == Z_Records_DBOSD)
    {
        srw_res->num_records =
            records->u.databaseOrSurDiagnostics->num_records;
        int i;
        srw_res->records = (Z_SRW_record *)
            odr_malloc(o, srw_res->num_records * sizeof(Z_SRW_record));
        for (i = 0; i < srw_res->num_records; i++)
        {
            Z_NamePlusRecord *npr = records->u.databaseOrSurDiagnostics->records[i];
            if (npr->which != Z_NamePlusRecord_databaseRecord)
            {
                srw_res->records[i].recordSchema = "diagnostic";
                srw_res->records[i].recordPacking = m_s2z_packing;
                srw_res->records[i].recordData_buf = "67";
                srw_res->records[i].recordData_len = 2;
                srw_res->records[i].recordPosition = odr_intdup(o, i+start);
                continue;
            }
            Z_External *r = npr->u.databaseRecord;
            oident *ent = oid_getentbyoid(r->direct_reference);
            if (r->which == Z_External_octet && ent->value == VAL_TEXT_XML)
            {
                srw_res->records[i].recordSchema = m_schema;
                srw_res->records[i].recordPacking = m_s2z_packing;
                srw_res->records[i].recordData_buf = (char*)
                    r->u.octet_aligned->buf;
                srw_res->records[i].recordData_len = r->u.octet_aligned->len;
                srw_res->records[i].recordPosition = odr_intdup(o, i+start);
            }
            else
            {
                srw_res->records[i].recordSchema = "diagnostic";
                srw_res->records[i].recordPacking = m_s2z_packing;
                srw_res->records[i].recordData_buf = "67";
                srw_res->records[i].recordData_len = 2;
                srw_res->records[i].recordPosition = odr_intdup(o, i+start);
            }
        }
    }
    if (records && records->which == Z_Records_NSD)
    {
        int http_code;
        http_code = z_to_srw_diag(odr_encode(), srw_res,
                                   records->u.nonSurrogateDiagnostic);
        if (http_code)
            return send_http_response(http_code);
    }
    return send_srw_response(srw_pdu);

}

int Yaz_Proxy::send_srw_search_response(Z_SRW_diagnostic *diagnostics,
                                        int num_diagnostics, int http_code /* = 200 */)
{
    ODR o = odr_encode();
    Z_SRW_PDU *srw_pdu = yaz_srw_get(o, Z_SRW_searchRetrieve_response);
    Z_SRW_searchRetrieveResponse *srw_res = srw_pdu->u.response;

    srw_res->num_diagnostics = num_diagnostics;
    srw_res->diagnostics = diagnostics;
    return send_srw_response(srw_pdu, http_code);
}

int Yaz_Proxy::send_srw_explain_response(Z_SRW_diagnostic *diagnostics,
                                        int num_diagnostics)
{
    Yaz_ProxyConfig *cfg = check_reconfigure();
    if (cfg)
    {
        int len;
        char *b = cfg->get_explain_doc(odr_encode(), 0 /* target */,
                                       m_s2z_database, &len);
        if (b)
        {
            Z_SRW_PDU *res = yaz_srw_get(odr_encode(), Z_SRW_explain_response);
            Z_SRW_explainResponse *er = res->u.explain_response;

            er->record.recordData_buf = b;
            er->record.recordData_len = len;
            er->record.recordPacking = m_s2z_packing;
            er->record.recordSchema = "http://explain.z3950.org/dtd/2.0/";

            er->diagnostics = diagnostics;
            er->num_diagnostics = num_diagnostics;
            return send_srw_response(res);
        }
    }
    return send_http_response(404);
}

int Yaz_Proxy::send_PDU_convert(Z_APDU *apdu)
{
    if (m_http_version)
    {
        if (apdu->which == Z_APDU_initResponse)
        {
            Z_InitResponse *res = apdu->u.initResponse;
            if (*res->result == 0)
            {
                send_to_srw_client_error(3, 0);
            }
            else if (!m_s2z_search_apdu)
            {
                send_srw_explain_response(0, 0);
            }
            else
            {
                handle_incoming_Z_PDU(m_s2z_search_apdu);
            }
        }
        else if (m_s2z_search_apdu && apdu->which == Z_APDU_searchResponse)
        {
            m_s2z_search_apdu = 0;
            Z_SearchResponse *res = apdu->u.searchResponse;
            m_s2z_hit_count = *res->resultCount;
            if (res->records && res->records->which == Z_Records_NSD)
            {
                send_to_srw_client_ok(0, res->records, 1);
            }
            else if (m_s2z_present_apdu && m_s2z_hit_count > 0)
            {
                // adjust
                Z_PresentRequest *pr = m_s2z_present_apdu->u.presentRequest;

                if (*pr->resultSetStartPoint <= m_s2z_hit_count)
                {
                    if (*pr->numberOfRecordsRequested+ *pr->resultSetStartPoint
                        > m_s2z_hit_count)
                        *pr->numberOfRecordsRequested =
                            1 + m_s2z_hit_count - *pr->resultSetStartPoint;
                }
                handle_incoming_Z_PDU(m_s2z_present_apdu);
            }
            else
            {
                m_s2z_present_apdu = 0;
                send_to_srw_client_ok(m_s2z_hit_count, res->records, 1);
            }
        }
        else if (m_s2z_present_apdu && apdu->which == Z_APDU_presentResponse)
        {
            int start =
                *m_s2z_present_apdu->u.presentRequest->resultSetStartPoint;

            m_s2z_present_apdu = 0;
            Z_PresentResponse *res = apdu->u.presentResponse;
            send_to_srw_client_ok(m_s2z_hit_count, res->records, start);
        }
    }
    else
    {
        int len = 0;
        if (m_log_mask & PROXY_LOG_REQ_CLIENT)
            yaz_log (YLOG_LOG, "%sSending %s to client", m_session_str,
                     apdu_name(apdu));
        int r = send_Z_PDU(apdu, &len);
        m_bytes_sent += len;
        m_bw_stat.add_bytes(len);
        logtime();
        return r;
    }
    return 0;
}

int Yaz_Proxy::send_to_client(Z_APDU *apdu)
{
    int kill_session = 0;
    Z_ReferenceId **new_id = get_referenceIdP(apdu);

    if (new_id)
        *new_id = m_referenceId;

    if (apdu->which == Z_APDU_searchResponse)
    {
        Z_SearchResponse *sr = apdu->u.searchResponse;
        Z_Records *p = sr->records;
        if (p && p->which == Z_Records_NSD)
        {
            Z_DiagRec dr, *dr_p = &dr;
            dr.which = Z_DiagRec_defaultFormat;
            dr.u.defaultFormat = p->u.nonSurrogateDiagnostic;

            *sr->searchStatus = 0;
            display_diagrecs(&dr_p, 1);
        }
        else
        {
            if (p && p->which == Z_Records_DBOSD)
            {
                if (m_backend_type
#if HAVE_USEMARCON
                    || m_usemarcon_ini_stage1 || m_usemarcon_ini_stage2
#endif
                    )
                    convert_to_frontend_type(p->u.databaseOrSurDiagnostics);
                if (m_marcxml_mode == marcxml)
                    convert_to_marcxml(p->u.databaseOrSurDiagnostics,
                                       m_backend_charset);
                else
                    convert_records_charset(p->u.databaseOrSurDiagnostics,
                                            m_backend_charset);
                if (convert_xsl(p->u.databaseOrSurDiagnostics, apdu))
                    return 0;

            }
            if (sr->resultCount)
            {
                yaz_log(YLOG_LOG, "%s%d hits", m_session_str,
                        *sr->resultCount);
                if (*sr->resultCount < 0)
                {
                    m_flag_invalid_session = 1;
                    kill_session = 1;

                    *sr->searchStatus = 0;
                    sr->records =
                        create_nonSurrogateDiagnostics(odr_encode(), 2, 0);
                    *sr->resultCount = 0;
                }
            }
        }
    }
    else if (apdu->which == Z_APDU_presentResponse)
    {
        Z_PresentResponse *sr = apdu->u.presentResponse;
        Z_Records *p = sr->records;
        if (p && p->which == Z_Records_NSD)
        {
            Z_DiagRec dr, *dr_p = &dr;
            dr.which = Z_DiagRec_defaultFormat;
            dr.u.defaultFormat = p->u.nonSurrogateDiagnostic;
            if (*sr->presentStatus == Z_PresentStatus_success)
                *sr->presentStatus = Z_PresentStatus_failure;
            display_diagrecs(&dr_p, 1);
        }
        if (p && p->which == Z_Records_DBOSD)
        {
            if (m_backend_type
#if HAVE_USEMARCON
                || m_usemarcon_ini_stage1 || m_usemarcon_ini_stage2
#endif
                )
                convert_to_frontend_type(p->u.databaseOrSurDiagnostics);
            if (m_marcxml_mode == marcxml)
                convert_to_marcxml(p->u.databaseOrSurDiagnostics,
                                   m_backend_charset);
            else
                convert_records_charset(p->u.databaseOrSurDiagnostics,
                                        m_backend_charset);
            if (convert_xsl(p->u.databaseOrSurDiagnostics, apdu))
                return 0;
        }
    }
    else if (apdu->which == Z_APDU_initResponse)
    {
        //Get and check negotiation record
        //from init response.
        handle_charset_lang_negotiation(apdu);

        if (m_initRequest_options)
        {
            Z_Options *nopt =
                (Odr_bitmask *)odr_malloc(odr_encode(),
                                          sizeof(Odr_bitmask));
            ODR_MASK_ZERO(nopt);

            int i;
            for (i = 0; i<24; i++)
                if (ODR_MASK_GET(m_initRequest_options, i) &&
                    ODR_MASK_GET(apdu->u.initResponse->options, i))
                    ODR_MASK_SET(nopt, i);
            apdu->u.initResponse->options = nopt;
        }
        if (m_initRequest_version)
        {
            Z_ProtocolVersion *nopt =
                (Odr_bitmask *)odr_malloc(odr_encode(),
                                          sizeof(Odr_bitmask));
            ODR_MASK_ZERO(nopt);

            int i;
            for (i = 0; i<8; i++)
                if (ODR_MASK_GET(m_initRequest_version, i) &&
                    ODR_MASK_GET(apdu->u.initResponse->protocolVersion, i))
                    ODR_MASK_SET(nopt, i);
            apdu->u.initResponse->protocolVersion = nopt;
        }
        apdu->u.initResponse->preferredMessageSize =
            odr_intdup(odr_encode(),
                       m_client->m_initResponse_preferredMessageSize >
                       m_initRequest_preferredMessageSize ?
                       m_initRequest_preferredMessageSize :
                       m_client->m_initResponse_preferredMessageSize);
        apdu->u.initResponse->maximumRecordSize =
            odr_intdup(odr_encode(),
                       m_client->m_initResponse_maximumRecordSize >
                       m_initRequest_maximumRecordSize ?
                       m_initRequest_maximumRecordSize :
                       m_client->m_initResponse_maximumRecordSize);
    }

    int r = send_PDU_convert(apdu);
    if (r)
        return r;
    if (kill_session)
    {
        delete m_client;
        m_client = 0;
        m_parent->pre_init();
    }
    return r;
}

void Yaz_ProxyClient::set_idAuthentication(Z_APDU *apdu)
{
    Z_IdAuthentication *t = apdu->u.initRequest->idAuthentication;
    
    odr_reset(m_idAuthentication_odr);
    z_IdAuthentication(m_idAuthentication_odr, &t, 1, 0);
    m_idAuthentication_ber_buf =
        odr_getbuf(m_idAuthentication_odr, 
                   &m_idAuthentication_ber_size, 0);
}

bool Yaz_ProxyClient::compare_charset(Z_APDU *apdu)
{
    return true;
}

bool Yaz_ProxyClient::compare_idAuthentication(Z_APDU *apdu)
{
    Z_IdAuthentication *t = apdu->u.initRequest->idAuthentication;
    ODR odr = odr_createmem(ODR_ENCODE);

    z_IdAuthentication(odr, &t, 1, 0);
    int sz;
    char *buf = odr_getbuf(odr, &sz, 0);
    if (buf && m_idAuthentication_ber_buf
        && sz == m_idAuthentication_ber_size
        && !memcmp(m_idAuthentication_ber_buf, buf, sz))
    {
        odr_destroy(odr);
        return true;
    }
    odr_destroy(odr);
    if (!buf && !m_idAuthentication_ber_buf)
        return true;
    return false;
}

int Yaz_ProxyClient::send_to_target(Z_APDU *apdu)
{
    int len = 0;
    const char *apdu_name_tmp = apdu_name(apdu);
    int r = send_Z_PDU(apdu, &len);
    if (m_root->get_log_mask() & PROXY_LOG_REQ_SERVER)
        yaz_log (YLOG_LOG, "%sSending %s to %s %d bytes",
                 get_session_str(),
                 apdu_name_tmp, get_hostname(), len);
    m_bytes_sent += len;
    return r;
}

Z_APDU *Yaz_Proxy::result_set_optimize(Z_APDU *apdu)
{
    if (apdu->which == Z_APDU_presentRequest)
    {
        Z_PresentRequest *pr = apdu->u.presentRequest;
        int toget = *pr->numberOfRecordsRequested;
        int start = *pr->resultSetStartPoint;

        yaz_log(YLOG_LOG, "%sPresent %s %d+%d", m_session_str,
                pr->resultSetId, start, toget);

        if (*m_parent->m_optimize == '0')
            return apdu;

        if (!m_client->m_last_resultSetId)
        {
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentResponse);
            new_apdu->u.presentResponse->records =
                create_nonSurrogateDiagnostics(
                    odr_encode(), 
                    YAZ_BIB1_SPECIFIED_RESULT_SET_DOES_NOT_EXIST,
                    pr->resultSetId);
            send_to_client(new_apdu);
            return 0;
        }
        if (start < 1 || toget < 0)
        {
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentResponse);
            new_apdu->u.presentResponse->records =
                create_nonSurrogateDiagnostics(
                    odr_encode(), 
                    YAZ_BIB1_PRESENT_REQUEST_OUT_OF_RANGE, 
                    0);
            send_to_client(new_apdu);
            return 0;
        }
        if (!strcmp(m_client->m_last_resultSetId, pr->resultSetId))
        {
            if (start+toget-1 > m_client->m_last_resultCount)
            {
                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentResponse);
                new_apdu->u.presentResponse->records =
                    create_nonSurrogateDiagnostics(
                        odr_encode(), 
                        YAZ_BIB1_PRESENT_REQUEST_OUT_OF_RANGE,
                        0);
                send_to_client(new_apdu);
                return 0;
            }
            Z_NamePlusRecordList *npr;
#if 0
            yaz_log(YLOG_LOG, "%sCache lookup %d+%d syntax=%s",
                    m_session_str, start, toget, yaz_z3950oid_to_str(
                        pr->preferredRecordSyntax, &oclass));
#endif
            if (m_client->m_cache.lookup (odr_encode(), &npr, start, toget,
                                          pr->preferredRecordSyntax,
                                          pr->recordComposition))
            {
                yaz_log (YLOG_LOG, "%sReturned cached records for present request",
                         m_session_str);
                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentResponse);
                new_apdu->u.presentResponse->referenceId = pr->referenceId;

                new_apdu->u.presentResponse->numberOfRecordsReturned
                    = odr_intdup(odr_encode(), toget);

                new_apdu->u.presentResponse->records = (Z_Records*)
                    odr_malloc(odr_encode(), sizeof(Z_Records));
                new_apdu->u.presentResponse->records->which = Z_Records_DBOSD;
                new_apdu->u.presentResponse->records->u.databaseOrSurDiagnostics = npr;
                new_apdu->u.presentResponse->nextResultSetPosition =
                    odr_intdup(odr_encode(), start+toget);

                send_to_client(new_apdu);
                return 0;
            }
        }
    }

    if (apdu->which != Z_APDU_searchRequest)
        return apdu;
    Z_SearchRequest *sr = apdu->u.searchRequest;
    Yaz_Z_Query *this_query = new Yaz_Z_Query;
    Yaz_Z_Databases this_databases;

    this_databases.set(sr->num_databaseNames, (const char **)
                       sr->databaseNames);

    this_query->set_Z_Query(sr->query);

    // Check for non-negative piggyback params.
    if (*sr->smallSetUpperBound < 0
        || *sr->largeSetLowerBound < 0
        || *sr->mediumSetPresentNumber < 0)
    {
        Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);
        // Not a present request.. But can't find better diagnostic
        new_apdu->u.searchResponse->records =
            create_nonSurrogateDiagnostics(
                odr_encode(), 
                YAZ_BIB1_PRESENT_REQUEST_OUT_OF_RANGE, 0);
        send_to_client(new_apdu);
        return 0;
    }

    char query_str[4096];
    this_query->print(query_str, sizeof(query_str)-1);
    yaz_log(YLOG_LOG, "%sSearch %s", m_session_str, query_str);

    if (*m_parent->m_optimize != '0' &&
        m_client->m_last_ok && m_client->m_last_query &&
        m_client->m_last_query->match(this_query) &&
        !strcmp(m_client->m_last_resultSetId, sr->resultSetName) &&
        m_client->m_last_databases.match(this_databases))
    {
        delete this_query;
        if (m_client->m_last_resultCount > *sr->smallSetUpperBound &&
            m_client->m_last_resultCount < *sr->largeSetLowerBound)
        {
            Z_NamePlusRecordList *npr;
            int toget = *sr->mediumSetPresentNumber;
            Z_RecordComposition *comp = 0;

            if (toget > m_client->m_last_resultCount)
                toget = m_client->m_last_resultCount;
            
            if (sr->mediumSetElementSetNames)
            {
                comp = (Z_RecordComposition *)
                    odr_malloc(odr_encode(), sizeof(Z_RecordComposition));
                comp->which = Z_RecordComp_simple;
                comp->u.simple = sr->mediumSetElementSetNames;
            }

            if (m_client->m_cache.lookup (odr_encode(), &npr, 1, toget,
                                          sr->preferredRecordSyntax, comp))
            {
                yaz_log (YLOG_LOG, "%sReturned cached records for medium set",
                         m_session_str);
                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);
                new_apdu->u.searchResponse->referenceId = sr->referenceId;
                new_apdu->u.searchResponse->resultCount =
                    &m_client->m_last_resultCount;

                new_apdu->u.searchResponse->numberOfRecordsReturned
                    = odr_intdup(odr_encode(), toget);

                new_apdu->u.searchResponse->presentStatus =
                    odr_intdup(odr_encode(), Z_PresentStatus_success);
                new_apdu->u.searchResponse->records = (Z_Records*)
                    odr_malloc(odr_encode(), sizeof(Z_Records));
                new_apdu->u.searchResponse->records->which = Z_Records_DBOSD;
                new_apdu->u.searchResponse->records->u.databaseOrSurDiagnostics = npr;
                new_apdu->u.searchResponse->nextResultSetPosition =
                    odr_intdup(odr_encode(), toget+1);
                send_to_client(new_apdu);
                return 0;
            }
            else
            {
                // medium Set
                // send present request (medium size)
                yaz_log (YLOG_LOG, "%sOptimizing search for medium set",
                         m_session_str);

                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentRequest);
                Z_PresentRequest *pr = new_apdu->u.presentRequest;
                pr->referenceId = sr->referenceId;
                pr->resultSetId = sr->resultSetName;
                pr->preferredRecordSyntax = sr->preferredRecordSyntax;
                *pr->numberOfRecordsRequested = toget;
                pr->recordComposition = comp;
                m_client->m_sr_transform = 1;
                return new_apdu;
            }
        }
        else if (m_client->m_last_resultCount >= *sr->largeSetLowerBound ||
            m_client->m_last_resultCount <= 0)
        {
            // large set. Return pseudo-search response immediately
            yaz_log (YLOG_LOG, "%sOptimizing search for large set",
                     m_session_str);
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);
            new_apdu->u.searchResponse->referenceId = sr->referenceId;
            new_apdu->u.searchResponse->resultCount =
                &m_client->m_last_resultCount;
            send_to_client(new_apdu);
            return 0;
        }
        else
        {
            Z_NamePlusRecordList *npr;
            int toget = m_client->m_last_resultCount;
            Z_RecordComposition *comp = 0;
            // small set
            // send a present request (small set)

            if (sr->smallSetElementSetNames)
            {
                comp = (Z_RecordComposition *)
                    odr_malloc(odr_encode(), sizeof(Z_RecordComposition));
                comp->which = Z_RecordComp_simple;
                comp->u.simple = sr->smallSetElementSetNames;
            }

            if (m_client->m_cache.lookup (odr_encode(), &npr, 1, toget,
                                          sr->preferredRecordSyntax, comp))
            {
                yaz_log (YLOG_LOG, "%sReturned cached records for small set",
                         m_session_str);
                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);
                new_apdu->u.searchResponse->referenceId = sr->referenceId;
                new_apdu->u.searchResponse->resultCount =
                    &m_client->m_last_resultCount;

                new_apdu->u.searchResponse->numberOfRecordsReturned
                    = odr_intdup(odr_encode(), toget);

                new_apdu->u.searchResponse->presentStatus =
                    odr_intdup(odr_encode(), Z_PresentStatus_success);
                new_apdu->u.searchResponse->records = (Z_Records*)
                    odr_malloc(odr_encode(), sizeof(Z_Records));
                new_apdu->u.searchResponse->records->which = Z_Records_DBOSD;
                new_apdu->u.searchResponse->records->u.databaseOrSurDiagnostics = npr;
                new_apdu->u.searchResponse->nextResultSetPosition =
                    odr_intdup(odr_encode(), toget+1);
                send_to_client(new_apdu);
                return 0;
            }
            else
            {
                yaz_log (YLOG_LOG, "%sOptimizing search for small set",
                         m_session_str);
                Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentRequest);
                Z_PresentRequest *pr = new_apdu->u.presentRequest;
                pr->referenceId = sr->referenceId;
                pr->resultSetId = sr->resultSetName;
                pr->preferredRecordSyntax = sr->preferredRecordSyntax;
                *pr->numberOfRecordsRequested = toget;
                pr->recordComposition = comp;
                m_client->m_sr_transform = 1;
                return new_apdu;
            }
        }
    }
    else  // query doesn't match
    {
        delete m_client->m_last_query;
        m_client->m_last_query = this_query;
        m_client->m_last_ok = 0;
        m_client->m_cache.clear();
        m_client->m_resultSetStartPoint = 0;

        xfree (m_client->m_last_resultSetId);
        m_client->m_last_resultSetId = xstrdup (sr->resultSetName);

        m_client->m_last_databases.set(sr->num_databaseNames,
                                       (const char **) sr->databaseNames);
    }
    return apdu;
}


void Yaz_Proxy::inc_request_no()
{
    m_request_no++;
    char *cp = m_session_str + strlen(m_session_str)-1;
    if (*cp == ' ')
        cp--;
    while (*cp && *cp != ' ')
        cp--;
    if (*cp)
        sprintf(cp+1, "%d ", m_request_no);
}

void Yaz_Proxy::recv_GDU(Z_GDU *apdu, int len)
{
    inc_request_no();

    m_bytes_recv += len;

    if (m_log_mask & PROXY_LOG_REQ_CLIENT)
        yaz_log (YLOG_LOG, "%sReceiving %s from client %d bytes",
                 m_session_str, gdu_name(apdu), len);

#if 0
    // try to make a _bad_ attribute set ID .. Don't enable this in prod.
    if (apdu->which == Z_GDU_Z3950 
        && apdu->u.z3950->which == Z_APDU_searchRequest)
    {
        Z_SearchRequest *req = apdu->u.z3950->u.searchRequest;
        if (req->query && req->query->which == Z_Query_type_1)
        {
            Z_RPNQuery *rpnquery = req->query->u.type_1;
            if (rpnquery->attributeSetId)
            {
                rpnquery->attributeSetId[0] = -2;
                rpnquery->attributeSetId[1] = -1;
                yaz_log(YLOG_WARN, "%sBAD FIXUP TEST", m_session_str);
            }
        }
    }
#endif

#if HAVE_GETTIMEOFDAY
    gettimeofday((struct timeval *) m_time_tv, 0);
#endif
    m_bw_stat.add_bytes(len);
    m_pdu_stat.add_bytes(1);

    GDU *gdu = new GDU(apdu);

    if (gdu->get() == 0)
    {
        delete gdu;
        yaz_log(YLOG_LOG, "%sUnable to encode package", m_session_str);
        m_in_queue.clear();
        dec_ref();
        return;
    }
    m_in_queue.enqueue(gdu);
    recv_GDU_more(false);
}

void Yaz_Proxy::HTTP_Forwarded(Z_GDU *z_gdu)
{
    if (z_gdu->which == Z_GDU_HTTP_Request)
    {
        Z_HTTP_Request *hreq = z_gdu->u.HTTP_Request;
        const char *x_forwarded_for =
            z_HTTP_header_lookup(hreq->headers, "X-Forwarded-For");
        if (x_forwarded_for)
        {
            xfree(m_peername);
            m_peername = (char*) xmalloc(strlen(x_forwarded_for)+5);
            sprintf(m_peername, "tcp:%s", x_forwarded_for);
            
            yaz_log(YLOG_LOG, "%sHTTP Forwarded from %s", m_session_str,
                    m_peername);
            if (m_log_mask & PROXY_LOG_IP_CLIENT)
                sprintf(m_session_str, "%ld:%d %.80s %d ",
                        (long) time(0), m_session_no, m_peername, m_request_no);
            else
                sprintf(m_session_str, "%ld:%d %d ",
                        (long) time(0), m_session_no, m_request_no);
        }
    }
}

void Yaz_Proxy::connect_stat(bool &block, int &reduce)
{

    m_parent->m_connect.cleanup(false);
    m_parent->m_connect.add_connect(m_peername);

    int connect_total = m_parent->m_connect.get_total(m_peername);
    int max_connect = m_parent->m_max_connect;

    if (max_connect && connect_total > max_connect)
    {
        yaz_log(YLOG_LOG, "%sconnect not accepted total=%d max=%d",
                m_session_str, connect_total, max_connect);
        block = true;
    }
    else 
        block = false;
    yaz_log(YLOG_LOG, "%sconnect accepted total=%d", m_session_str,
            connect_total);
    
    int limit_connect = m_parent->m_limit_connect;
    if (limit_connect)
        reduce = connect_total / limit_connect;
    else
        reduce = 0;
}

void Yaz_Proxy::recv_GDU_reduce(GDU *gdu)
{
    HTTP_Forwarded(gdu->get());

    int reduce = 0;
    
    if (m_request_no == 1)
    {
        bool block = false;
        
        connect_stat(block, reduce);

        if (block)
        {
            m_timeout_mode = timeout_busy;
            timeout(0);
            return;
        }
    }

    int bw_total = m_bw_stat.get_total();
    int pdu_total = m_pdu_stat.get_total();
    int search_total = m_search_stat.get_total();

    assert(m_timeout_mode == timeout_busy);
    assert(m_timeout_gdu == 0);

    if (m_search_max)
        reduce += search_total / m_search_max;
    if (m_bw_max)
        reduce += (bw_total/m_bw_max);
    if (m_pdu_max)
    {
        if (pdu_total > m_pdu_max)
        {
            int nreduce = (m_pdu_max >= 60) ? 1 : 60/m_pdu_max;
            reduce = (reduce > nreduce) ? reduce : nreduce;
        }
    }
    m_http_version = 0;

#if 0
    /* uncomment to force a big reduce */
    m_timeout_mode = timeout_reduce;
    m_timeout_gdu = gdu;
    timeout(3);       // call us reduce seconds later
    return;
#endif
    if (reduce)
    {
        yaz_log(YLOG_LOG, "%sdelay=%d bw=%d pdu=%d search=%d limit-bw=%d limit-pdu=%d limit-search=%d",
                m_session_str, reduce, bw_total, pdu_total, search_total,
                m_bw_max, m_pdu_max, m_search_max);

        m_timeout_mode = timeout_reduce;
        m_timeout_gdu = gdu;
        timeout(reduce);       // call us reduce seconds later
    }
    else
        recv_GDU_normal(gdu);
}

void Yaz_Proxy::recv_GDU_more(bool normal)
{
    GDU *g;
    if (normal && m_timeout_mode == timeout_busy)
        m_timeout_mode = timeout_normal;
    while (m_timeout_mode == timeout_normal && (g = m_in_queue.dequeue()))
    {
        m_timeout_mode = timeout_busy;
        inc_ref();
        recv_GDU_reduce(g);
        if (dec_ref())
            break;
    }
}

void Yaz_Proxy::recv_GDU_normal(GDU *gdu)
{
    Z_GDU *apdu = 0;
    gdu->move_away_gdu(odr_decode(), &apdu);
    delete gdu;

    if (apdu->which == Z_GDU_Z3950)
        handle_incoming_Z_PDU(apdu->u.z3950);
    else if (apdu->which == Z_GDU_HTTP_Request)
        handle_incoming_HTTP(apdu->u.HTTP_Request);
}

void Yaz_Proxy::handle_max_record_retrieve(Z_APDU *apdu)
{
    if (m_max_record_retrieve)
    {
        if (apdu->which == Z_APDU_presentRequest)
        {
            Z_PresentRequest *pr = apdu->u.presentRequest;
            if (pr->numberOfRecordsRequested &&
                *pr->numberOfRecordsRequested > m_max_record_retrieve)
                *pr->numberOfRecordsRequested = m_max_record_retrieve;
        }
    }
}

void Yaz_Proxy::handle_charset_lang_negotiation(Z_APDU *apdu)
{
    if (apdu->which == Z_APDU_initRequest)
    {
        if (m_initRequest_options &&
            !ODR_MASK_GET(m_initRequest_options, Z_Options_negotiationModel) &&
            (m_proxy_negotiation_charset || m_proxy_negotiation_lang))
        {
            // There is no negotiation proposal from
            // client's side. OK. The proxy negotiation
            // in use, only.
            Z_InitRequest *initRequest = apdu->u.initRequest;
            Z_OtherInformation **otherInfo;
            Z_OtherInformationUnit *oi;
            get_otherInfoAPDU(apdu, &otherInfo);
            oi = update_otherInformation(otherInfo, 1, NULL, 0, 0);
            if (oi)
            {
                ODR_MASK_SET(initRequest->options,
                    Z_Options_negotiationModel);
                oi->which = Z_OtherInfo_externallyDefinedInfo;
                oi->information.externallyDefinedInfo =
                yaz_set_proposal_charneg(odr_encode(),
                    (const char**)&m_proxy_negotiation_charset,
                    m_proxy_negotiation_charset ? 1:0,
                    (const char**)&m_proxy_negotiation_lang,
                    m_proxy_negotiation_lang ? 1:0,
                    1);
            }
        }
        else if (m_initRequest_options &&
                 ODR_MASK_GET(m_initRequest_options,
                              Z_Options_negotiationModel) &&
                 m_charset_converter->get_target_query_charset())
        {
            yaz_log(YLOG_LOG, "%sManaged charset negotiation: charset=%s",
                    m_session_str,
                    m_charset_converter->get_target_query_charset());
            Z_InitRequest *initRequest = apdu->u.initRequest;
            Z_CharSetandLanguageNegotiation *negotiation =
                yaz_get_charneg_record (initRequest->otherInfo);
            if (negotiation &&
                negotiation->which == Z_CharSetandLanguageNegotiation_proposal)
            {
                NMEM nmem = nmem_create();
                char **charsets = 0;
                int num_charsets = 0;
                char **langs = 0;
                int num_langs = 0;
                int selected = 0;
                yaz_get_proposal_charneg (nmem, negotiation,
                                          &charsets, &num_charsets,
                                          &langs, &num_langs, &selected);
                int i;
                for (i = 0; i<num_charsets; i++)
                    yaz_log(YLOG_LOG, "%scharset %s", m_session_str,
                            charsets[i]);
                for (i = 0; i<num_langs; i++)
                    yaz_log(YLOG_LOG, "%slang %s", m_session_str,
                            langs[i]);

                const char *t_charset =
                    m_charset_converter->get_target_query_charset();
                // sweep through charsets and pick the first supported
                // conversion
                for (i = 0; i<num_charsets; i++)
                {
                    const char *c_charset = charsets[i];
                    if (!odr_set_charset(odr_decode(), t_charset, c_charset))
                        break;
                }
                if (i != num_charsets)
                {
                    // got one .. set up ODR for reverse direction
                    const char *c_charset = charsets[i];
                    odr_set_charset(odr_encode(), c_charset, t_charset);
                    m_charset_converter->set_client_query_charset(c_charset);
                    m_charset_converter->set_client_charset_selected(selected);
                }
                nmem_destroy(nmem);
                ODR_MASK_CLEAR(m_initRequest_options,
                               Z_Options_negotiationModel);
                yaz_del_charneg_record(&initRequest->otherInfo);
            }
            else
            {
                yaz_log(YLOG_WARN, "%sUnable to decode charset package",
                        m_session_str);
            }
        }
        else if (m_charset_converter->get_target_query_charset() &&
            m_proxy_negotiation_default_charset)
        {
            m_charset_converter->
                set_client_query_charset(m_proxy_negotiation_default_charset);
        }
    }
    else if (apdu->which == Z_APDU_initResponse)
    {
        Z_InitResponse *initResponse = apdu->u.initResponse;
        Z_OtherInformation **otherInfo;
        get_otherInfoAPDU(apdu, &otherInfo);
        
        Z_CharSetandLanguageNegotiation *charneg = 0;

        if (otherInfo && *otherInfo && 
            ODR_MASK_GET(initResponse->options, Z_Options_negotiationModel)
            && (charneg = yaz_get_charneg_record(*otherInfo)))
        {
            char *charset = 0;
            char *lang = 0;
            int selected = 0;

            yaz_get_response_charneg(m_referenceId_mem, charneg,
                &charset, &lang, &selected);

            yaz_log(YLOG_LOG, "%sAccepted charset - '%s' and lang - '%s'",
                m_session_str, (charset)?charset:"none", (lang)?lang:"none");

            if (m_initRequest_options &&
                ODR_MASK_GET(m_initRequest_options, Z_Options_negotiationModel))
            {
                yaz_log(YLOG_LOG, "%sClient's negotiation record in use",
                    m_session_str);
            }
            else if (m_proxy_negotiation_charset || m_proxy_negotiation_lang)
            {
                // negotiation-charset, negotiation-lang
                // elements of config file in use.

                yaz_log(YLOG_LOG, "%sProxy's negotiation record in use",
                    m_session_str);

                // clear negotiation option.
                ODR_MASK_CLEAR(initResponse->options, Z_Options_negotiationModel);

                // Delete negotiation (charneg-3) entry.
                yaz_del_charneg_record(otherInfo);
            }
        }
        else
        {
            if (m_proxy_negotiation_charset || m_proxy_negotiation_lang)
            {
                yaz_log(YLOG_LOG, "%sTarget did not honor negotiation",
                        m_session_str);
            }
            else if (m_charset_converter->get_client_query_charset())
            {
                Z_OtherInformation **otherInfo;
                Z_OtherInformationUnit *oi;
                get_otherInfoAPDU(apdu, &otherInfo);
                oi = update_otherInformation(otherInfo, 1, NULL, 0, 0);
                if (oi)
                {
                    ODR_MASK_SET(initResponse->options,
                                 Z_Options_negotiationModel);
                    if (m_initRequest_options)
                        ODR_MASK_SET(m_initRequest_options,
                                     Z_Options_negotiationModel);
                    
                    oi->which = Z_OtherInfo_externallyDefinedInfo;    
                    oi->information.externallyDefinedInfo =
                        yaz_set_response_charneg(
                            odr_encode(),
                            m_charset_converter->get_client_query_charset(),
                            0 /* no lang */,
                            m_charset_converter->get_client_charset_selected());
                }
            }
        }
    }
}

Z_Records *Yaz_Proxy::create_nonSurrogateDiagnostics(ODR odr,
                                                     int error,
                                                     const char *addinfo)
{
    Z_Records *rec = (Z_Records *)
        odr_malloc (odr, sizeof(*rec));
    int *err = (int *)
        odr_malloc (odr, sizeof(*err));
    Z_DiagRec *drec = (Z_DiagRec *)
        odr_malloc (odr, sizeof(*drec));
    Z_DefaultDiagFormat *dr = (Z_DefaultDiagFormat *)
        odr_malloc (odr, sizeof(*dr));
    *err = error;
    rec->which = Z_Records_NSD;
    rec->u.nonSurrogateDiagnostic = dr;
    dr->diagnosticSetId =
        yaz_oidval_to_z3950oid (odr, CLASS_DIAGSET, VAL_BIB1);
    dr->condition = err;
    dr->which = Z_DefaultDiagFormat_v2Addinfo;
    dr->u.v2Addinfo = odr_strdup (odr, addinfo ? addinfo : "");
    return rec;
}

Z_APDU *Yaz_Proxy::handle_query_transformation(Z_APDU *apdu)
{
    if (apdu->which == Z_APDU_searchRequest &&
        apdu->u.searchRequest->query &&
        apdu->u.searchRequest->query->which == Z_Query_type_104 &&
        apdu->u.searchRequest->query->u.type_104->which == Z_External_CQL)
    {
        Z_RPNQuery *rpnquery = 0;
        Z_SearchRequest *sr = apdu->u.searchRequest;
        char *addinfo = 0;

        yaz_log(YLOG_LOG, "%sCQL: %s", m_session_str,
                sr->query->u.type_104->u.cql);

        int r = m_cql2rpn.query_transform(sr->query->u.type_104->u.cql,
                                          &rpnquery, odr_encode(),
                                          &addinfo);
        if (r == -3)
            yaz_log(YLOG_LOG, "%sNo CQL to RPN table", m_session_str);
        else if (r)
        {
            yaz_log(YLOG_LOG, "%sCQL Conversion error %d", m_session_str, r);
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);

            new_apdu->u.searchResponse->referenceId = sr->referenceId;
            new_apdu->u.searchResponse->records =
                create_nonSurrogateDiagnostics(odr_encode(),
                                               yaz_diag_srw_to_bib1(r),
                                               addinfo);
            *new_apdu->u.searchResponse->searchStatus = 0;

            send_to_client(new_apdu);

            return 0;
        }
        else
        {
            sr->query->which = Z_Query_type_1;
            sr->query->u.type_1 = rpnquery;
        }
        return apdu;
    }
    return apdu;
}

Z_APDU *Yaz_Proxy::handle_target_charset_conversion(Z_APDU *apdu)
{
    if (apdu->which == Z_APDU_searchRequest &&
        apdu->u.searchRequest->query)
    {
        if (apdu->u.searchRequest->query->which == Z_Query_type_1
            || apdu->u.searchRequest->query->which == Z_Query_type_101)
        {
            if (m_http_version)
                m_charset_converter->set_client_query_charset("UTF-8");
            Z_RPNQuery *rpnquery = apdu->u.searchRequest->query->u.type_1;
            m_charset_converter->convert_type_1(rpnquery, odr_encode());
        }
    }
    return apdu;
}


Z_APDU *Yaz_Proxy::handle_query_validation(Z_APDU *apdu)
{
    if (apdu->which == Z_APDU_searchRequest)
    {
        Z_SearchRequest *sr = apdu->u.searchRequest;
        int err = 0;
        char *addinfo = 0;

        Yaz_ProxyConfig *cfg = check_reconfigure();
        if (cfg)
            err = cfg->check_query(odr_encode(), m_default_target,
                                   sr->query, &addinfo);
        if (err)
        {
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);

            new_apdu->u.searchResponse->referenceId = sr->referenceId;
            new_apdu->u.searchResponse->records =
                create_nonSurrogateDiagnostics(odr_encode(), err, addinfo);
            *new_apdu->u.searchResponse->searchStatus = 0;

            send_to_client(new_apdu);

            return 0;
        }
    }
    return apdu;
}

int Yaz_Proxy::handle_authentication(Z_APDU *apdu)
{
    if (apdu->which != Z_APDU_initRequest)
        return 1;  // pass if no init request
    Z_InitRequest *req = apdu->u.initRequest;

    Yaz_ProxyConfig *cfg = check_reconfigure();
    if (!cfg)
        return 1;  // pass if no config

    int ret;
    if (req->idAuthentication == 0)
    {
        ret = cfg->client_authentication(m_default_target, 0, 0, 0,
                                         m_peername);
    }
    else if (req->idAuthentication->which == Z_IdAuthentication_idPass)
    {
        ret = cfg->client_authentication(
            m_default_target,
            req->idAuthentication->u.idPass->userId,
            req->idAuthentication->u.idPass->groupId,
            req->idAuthentication->u.idPass->password,
            m_peername);
    }
    else if (req->idAuthentication->which == Z_IdAuthentication_open)
    {
        char user[64], pass[64];
        *user = '\0';
        *pass = '\0';
        sscanf(req->idAuthentication->u.open, "%63[^/]/%63s", user, pass);
        ret = cfg->client_authentication(m_default_target, user, 0, pass,
                                         m_peername);
    }
    else
        ret = cfg->client_authentication(m_default_target, 0, 0, 0,
                                         m_peername);
    return ret;
}

int Yaz_Proxy::handle_global_authentication(Z_APDU *apdu)
{
    if (apdu->which != Z_APDU_initRequest)
        return 1;  // pass if no init request
    Z_InitRequest *req = apdu->u.initRequest;

    Yaz_ProxyConfig *cfg = check_reconfigure();
    if (!cfg)
        return 1;  // pass if no config

    int ret;
    if (req->idAuthentication == 0)
    {
        ret = cfg->global_client_authentication(0, 0, 0,
                                                m_peername);
    }
    else if (req->idAuthentication->which == Z_IdAuthentication_idPass)
    {
        ret = cfg->global_client_authentication(
            req->idAuthentication->u.idPass->userId,
            req->idAuthentication->u.idPass->groupId,
            req->idAuthentication->u.idPass->password,
            m_peername);
    }
    else if (req->idAuthentication->which == Z_IdAuthentication_open)
    {
        char user[64], pass[64];
        *user = '\0';
        *pass = '\0';
        sscanf(req->idAuthentication->u.open, "%63[^/]/%63s", user, pass);
        ret = cfg->global_client_authentication(user, 0, pass,
                                                m_peername);
    }
    else
        ret = cfg->global_client_authentication(0, 0, 0, m_peername);
    return ret;
}

Z_APDU *Yaz_Proxy::handle_syntax_validation(Z_APDU *apdu)
{
    m_marcxml_mode = none;
    if (apdu->which == Z_APDU_searchRequest)
    {
        Z_SearchRequest *sr = apdu->u.searchRequest;
        int err = 0;
        char *addinfo = 0;
        Yaz_ProxyConfig *cfg = check_reconfigure();

        Z_RecordComposition rc_temp, *rc = 0;
        if (sr->smallSetElementSetNames)
        {
            rc_temp.which = Z_RecordComp_simple;
            rc_temp.u.simple = sr->smallSetElementSetNames;
            rc = &rc_temp;
        }

        if (sr->preferredRecordSyntax)
        {
            struct oident *ent;
            ent = oid_getentbyoid(sr->preferredRecordSyntax);
            m_frontend_type = ent->value;
        }
        else
            m_frontend_type = VAL_NONE;

        char *stylesheet_name = 0;
        if (cfg)
            err = cfg->check_syntax(odr_encode(),
                                    m_default_target,
                                    sr->preferredRecordSyntax, rc,
                                    &addinfo, &stylesheet_name, &m_schema,
                                    &m_backend_type, &m_backend_charset,
                                    &m_usemarcon_ini_stage1,
                                    &m_usemarcon_ini_stage2);
        if (stylesheet_name)
        {
            m_parent->low_socket_close();

#if YAZ_HAVE_XSLT
            if (m_stylesheet_xsp)
                xsltFreeStylesheet((xsltStylesheetPtr) m_stylesheet_xsp);
            m_stylesheet_xsp = xsltParseStylesheetFile((const xmlChar*)
                                                       stylesheet_name);
#endif
            m_stylesheet_offset = 0;
            xfree(stylesheet_name);

            m_parent->low_socket_open();
        }
        if (err == -1)
        {
            sr->smallSetElementSetNames = 0;
            sr->mediumSetElementSetNames = 0;
            m_marcxml_mode = marcxml;
            if (m_backend_type)
            {

                sr->preferredRecordSyntax =
                    yaz_str_to_z3950oid(odr_encode(), CLASS_RECSYN,
                                        m_backend_type);
            }
            else
                sr->preferredRecordSyntax =
                    yaz_oidval_to_z3950oid(odr_encode(), CLASS_RECSYN,
                                           VAL_USMARC);
        }
        else if (err)
        {
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);

            new_apdu->u.searchResponse->referenceId = sr->referenceId;
            new_apdu->u.searchResponse->records =
                create_nonSurrogateDiagnostics(odr_encode(), err, addinfo);
            *new_apdu->u.searchResponse->searchStatus = 0;

            send_to_client(new_apdu);

            return 0;
        }
        else if (m_backend_type)
        {
            sr->preferredRecordSyntax =
                yaz_str_to_z3950oid(odr_encode(), CLASS_RECSYN, m_backend_type);
        }
    }
    else if (apdu->which == Z_APDU_presentRequest)
    {
        Z_PresentRequest *pr = apdu->u.presentRequest;
        int err = 0;
        char *addinfo = 0;
        Yaz_ProxyConfig *cfg = check_reconfigure();

        if (pr->preferredRecordSyntax)
        {
            struct oident *ent;
            ent = oid_getentbyoid(pr->preferredRecordSyntax);
            m_frontend_type = ent->value;
        }
        else
            m_frontend_type = VAL_NONE;

        char *stylesheet_name = 0;
        if (cfg)
            err = cfg->check_syntax(odr_encode(), m_default_target,
                                    pr->preferredRecordSyntax,
                                    pr->recordComposition,
                                    &addinfo, &stylesheet_name, &m_schema,
                                    &m_backend_type, &m_backend_charset,
                                    &m_usemarcon_ini_stage1,
                                    &m_usemarcon_ini_stage2
                                    );
        if (stylesheet_name)
        {
            m_parent->low_socket_close();

#if YAZ_HAVE_XSLT
            if (m_stylesheet_xsp)
                xsltFreeStylesheet((xsltStylesheetPtr) m_stylesheet_xsp);
            m_stylesheet_xsp = xsltParseStylesheetFile((const xmlChar*)
                                                       stylesheet_name);
#endif
            m_stylesheet_offset = 0;
            xfree(stylesheet_name);

            m_parent->low_socket_open();
        }
        if (err == -1)
        {
            pr->recordComposition = 0;
            m_marcxml_mode = marcxml;
            if (m_backend_type)
            {

                pr->preferredRecordSyntax =
                    yaz_str_to_z3950oid(odr_encode(), CLASS_RECSYN,
                                        m_backend_type);
            }
            else
                pr->preferredRecordSyntax =
                    yaz_oidval_to_z3950oid(odr_encode(), CLASS_RECSYN,
                                           VAL_USMARC);
        }
        else if (err)
        {
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_presentResponse);

            new_apdu->u.presentResponse->referenceId = pr->referenceId;
            new_apdu->u.presentResponse->records =
                create_nonSurrogateDiagnostics(odr_encode(), err, addinfo);
            *new_apdu->u.presentResponse->presentStatus =
                Z_PresentStatus_failure;

            send_to_client(new_apdu);

            return 0;
        }
        else if (m_backend_type)
        {
            pr->preferredRecordSyntax =
                yaz_str_to_z3950oid(odr_encode(), CLASS_RECSYN, m_backend_type);
        }
    }
    return apdu;
}

Z_ElementSetNames *Yaz_Proxy::mk_esn_from_schema(ODR o, const char *schema)
{
    if (!schema)
        return 0;
    Z_ElementSetNames *esn = (Z_ElementSetNames *)
        odr_malloc(o, sizeof(Z_ElementSetNames));
    esn->which = Z_ElementSetNames_generic;
    esn->u.generic = odr_strdup(o, schema);
    return esn;
}

void Yaz_Proxy::srw_get_client(const char *db, const char **backend_db)
{
    const char *t = 0;
    Yaz_ProxyConfig *cfg = check_reconfigure();
    if (cfg)
        t = cfg->get_explain_name(db, backend_db);

    if (m_client && m_default_target && t && strcmp(m_default_target, t))
    {
        releaseClient();
    }

    if (t)
    {
        xfree(m_default_target);
        m_default_target = xstrdup(t);
    }
}

int Yaz_Proxy::file_access(Z_HTTP_Request *hreq)
{
    struct stat sbuf;
    if (strcmp(hreq->method, "GET"))
        return 0;
    if (hreq->path[0] != '/')
        return 0;
    const char *cp = hreq->path;
    while (*cp)
    {
        if (*cp == '/' && strchr("/.", cp[1]))
            return 0;
        cp++;
    }

    Yaz_ProxyConfig *cfg = check_reconfigure();

    if (!cfg->get_file_access_info(hreq->path+1))
        return 0;

    const char *fname = hreq->path+1;
    if (stat(fname, &sbuf))
    {
        yaz_log(YLOG_LOG|YLOG_ERRNO, "%sstat failed for %s", m_session_str,
                fname);
        return 0;
    }
    if ((sbuf.st_mode & S_IFMT) != S_IFREG)
    {
        yaz_log(YLOG_LOG, "%sNot a regular file %s", m_session_str, fname);
        return 0;
    }
    if (sbuf.st_size > (off_t) 1000000)
    {
        yaz_log(YLOG_WARN, "%sFile %s too large for transfer", m_session_str,
                fname);
        return 0;
    }

    ODR o = odr_encode();

    const char *ctype = cfg->check_mime_type(fname);
    Z_GDU *gdu = z_get_HTTP_Response(o, 200);
    Z_HTTP_Response *hres = gdu->u.HTTP_Response;
    if (m_http_version)
        hres->version = odr_strdup(o, m_http_version);
    z_HTTP_header_add(o, &hres->headers, "Content-Type", ctype);
    if (m_http_keepalive)
        z_HTTP_header_add(o, &hres->headers, "Connection", "Keep-Alive");
    else
        timeout(0);

    hres->content_len = sbuf.st_size;
    hres->content_buf = (char*) odr_malloc(o, hres->content_len);
    FILE *f = fopen(fname, "rb");
    if (f)
    {
        fread(hres->content_buf, 1, hres->content_len, f);
        fclose(f);
    }
    else
    {
        return 0;
    }
    if (m_log_mask & PROXY_LOG_REQ_CLIENT)
    {
        yaz_log (YLOG_LOG, "%sSending file %s to client", m_session_str,
                 fname);
    }
    int len;
    send_GDU(gdu, &len);
    recv_GDU_more(true);
    return 1;
}

void Yaz_Proxy::handle_incoming_HTTP(Z_HTTP_Request *hreq)
{
    if (m_s2z_odr_init)
    {
        odr_destroy(m_s2z_odr_init);
        m_s2z_odr_init = 0;
    }
    if (m_s2z_odr_search)
    {
        odr_destroy(m_s2z_odr_search);
        m_s2z_odr_search = 0;
    }

    m_http_keepalive = 0;
    m_http_version = 0;
    if (!strcmp(hreq->version, "1.0"))
    {
        const char *v = z_HTTP_header_lookup(hreq->headers, "Connection");
        if (v && !strcmp(v, "Keep-Alive"))
            m_http_keepalive = 1;
        else
            m_http_keepalive = 0;
        m_http_version = "1.0";
    }
    else
    {
        const char *v = z_HTTP_header_lookup(hreq->headers, "Connection");
        if (v && !strcmp(v, "close"))
            m_http_keepalive = 0;
        else
            m_http_keepalive = 1;
        m_http_version = "1.1";
    }

    const char *a = z_HTTP_header_lookup(hreq->headers, "Authorization");
    char authorization_str[255];
    *authorization_str = '\0';
    if (a && strncasecmp(a, "Basic ", 6) == 0)
        base64_decode(a + 6, authorization_str, 254);

    Z_SRW_PDU *srw_pdu = 0;
    Z_SOAP *soap_package = 0;
    char *charset = 0;
    Z_SRW_diagnostic *diagnostic = 0;
    int num_diagnostic = 0;

    yaz_log(YLOG_LOG, "%s%s %s", m_session_str, hreq->method, hreq->path);

    if (file_access(hreq))
    {
        return;
    }
    else if (yaz_srw_decode(hreq, &srw_pdu, &soap_package, odr_decode(),
                            &charset) == 0
             || yaz_sru_decode(hreq, &srw_pdu, &soap_package, odr_decode(),
                               &charset, &diagnostic, &num_diagnostic) == 0)
    {
        m_s2z_odr_init = odr_createmem(ODR_ENCODE);
        m_s2z_odr_search = odr_createmem(ODR_ENCODE);
        m_soap_ns = odr_strdup(m_s2z_odr_search, soap_package->ns);
        m_s2z_init_apdu = 0;
        m_s2z_search_apdu = 0;
        m_s2z_present_apdu = 0;

        m_s2z_stylesheet = 0;

        Z_IdAuthentication *auth = NULL;
        if (*authorization_str)
        {
            auth = (Z_IdAuthentication *) odr_malloc(m_s2z_odr_init, sizeof(Z_IdAuthentication));
            auth->which = Z_IdAuthentication_idPass;
            auth->u.idPass = (Z_IdPass *) odr_malloc(m_s2z_odr_init, sizeof(Z_IdPass));
            auth->u.idPass->groupId = NULL;
            char *p = strchr(authorization_str, ':');
            if (p)
            {
                *p = '\0';
                p++;
                auth->u.idPass->password = odr_strdup(m_s2z_odr_init, p);
            }
            auth->u.idPass->userId = odr_strdup(m_s2z_odr_init, authorization_str);
        }

        if (srw_pdu->which == Z_SRW_searchRetrieve_request)
        {

            Z_SRW_searchRetrieveRequest *srw_req = srw_pdu->u.request;

            const char *backend_db = srw_req->database;
            srw_get_client(srw_req->database, &backend_db);

            m_s2z_database = odr_strdup(m_s2z_odr_init, srw_req->database);
            // recordXPath unsupported.
            if (srw_req->recordXPath)
            {
                yaz_add_srw_diagnostic(odr_decode(),
                                       &diagnostic, &num_diagnostic,
                                       72, 0);
            }
            // sort unsupported
            if (srw_req->sort_type != Z_SRW_sort_type_none)
            {
                yaz_add_srw_diagnostic(odr_decode(),
                                       &diagnostic, &num_diagnostic,
                                       80, 0);
            }
            // save stylesheet
            if (srw_req->stylesheet)
                m_s2z_stylesheet =
                    odr_strdup(m_s2z_odr_init, srw_req->stylesheet);

            // set packing for response records ..
            if (srw_req->recordPacking &&
                !strcmp(srw_req->recordPacking, "xml"))
                m_s2z_packing = Z_SRW_recordPacking_XML;
            else
                m_s2z_packing = Z_SRW_recordPacking_string;

            if (num_diagnostic)
            {
                Z_SRW_PDU *srw_pdu =
                    yaz_srw_get(odr_encode(),
                                Z_SRW_searchRetrieve_response);
                Z_SRW_searchRetrieveResponse *srw_res = srw_pdu->u.response;

                srw_res->diagnostics = diagnostic;
                srw_res->num_diagnostics = num_diagnostic;
                send_srw_response(srw_pdu);
                return;
            }

            // prepare search PDU
            m_s2z_search_apdu = zget_APDU(m_s2z_odr_search,
                                          Z_APDU_searchRequest);
            Z_SearchRequest *z_searchRequest =
                m_s2z_search_apdu->u.searchRequest;

            z_searchRequest->num_databaseNames = 1;
            z_searchRequest->databaseNames = (char**)
                odr_malloc(m_s2z_odr_search, sizeof(char *));
            z_searchRequest->databaseNames[0] = odr_strdup(m_s2z_odr_search,
                                                           backend_db);

            // query transformation
            Z_Query *query = (Z_Query *)
                odr_malloc(m_s2z_odr_search, sizeof(Z_Query));
            z_searchRequest->query = query;

            if (srw_req->query_type == Z_SRW_query_type_cql)
            {
                Z_External *ext = (Z_External *)
                    odr_malloc(m_s2z_odr_search, sizeof(*ext));
                ext->direct_reference =
                    odr_getoidbystr(m_s2z_odr_search, "1.2.840.10003.16.2");
                ext->indirect_reference = 0;
                ext->descriptor = 0;
                ext->which = Z_External_CQL;
                ext->u.cql = srw_req->query.cql;

                query->which = Z_Query_type_104;
                query->u.type_104 =  ext;
            }
            else if (srw_req->query_type == Z_SRW_query_type_pqf)
            {
                Z_RPNQuery *RPNquery;
                YAZ_PQF_Parser pqf_parser;

                pqf_parser = yaz_pqf_create ();

                RPNquery = yaz_pqf_parse (pqf_parser, m_s2z_odr_search,
                                          srw_req->query.pqf);
                if (!RPNquery)
                {
                    const char *pqf_msg;
                    size_t off;
                    int code = yaz_pqf_error (pqf_parser, &pqf_msg, &off);
                    int ioff = off;
                    yaz_log(YLOG_LOG, "%*s^\n", ioff+4, "");
                    yaz_log(YLOG_LOG, "Bad PQF: %s (code %d)\n", pqf_msg, code);

                    send_to_srw_client_error(10, 0);
                    return;
                }
                query->which = Z_Query_type_1;
                query->u.type_1 =  RPNquery;

                yaz_pqf_destroy (pqf_parser);
            }
            else
            {
                send_to_srw_client_error(7, "query");
                return;
            }

            // present
            m_s2z_present_apdu = 0;
            int max = 0;
            if (srw_req->maximumRecords)
                max = *srw_req->maximumRecords;
            int start = 1;
            if (srw_req->startRecord)
                start = *srw_req->startRecord;
            if (max > 0)
            {
                // Some backend, such as Voyager doesn't honor piggyback
                // So we use present always (0 &&).
                if (0 && start <= 1)  // Z39.50 piggyback
                {
                    *z_searchRequest->smallSetUpperBound = max;
                    *z_searchRequest->mediumSetPresentNumber = max;
                    *z_searchRequest->largeSetLowerBound = 2000000000; // 2e9

                    z_searchRequest->preferredRecordSyntax =
                        yaz_oidval_to_z3950oid(m_s2z_odr_search, CLASS_RECSYN,
                                               VAL_TEXT_XML);
                    if (srw_req->recordSchema)
                    {
                        z_searchRequest->smallSetElementSetNames =
                            z_searchRequest->mediumSetElementSetNames =
                            mk_esn_from_schema(m_s2z_odr_search,
                                               srw_req->recordSchema);
                    }
                }
                else   // Z39.50 present
                {
                    m_s2z_present_apdu = zget_APDU(m_s2z_odr_search,
                                                   Z_APDU_presentRequest);
                    Z_PresentRequest *z_presentRequest =
                        m_s2z_present_apdu->u.presentRequest;
                    *z_presentRequest->resultSetStartPoint = start;
                    *z_presentRequest->numberOfRecordsRequested = max;
                    z_presentRequest->preferredRecordSyntax =
                        yaz_oidval_to_z3950oid(m_s2z_odr_search, CLASS_RECSYN,
                                               VAL_TEXT_XML);
                    if (srw_req->recordSchema)
                    {
                        z_presentRequest->recordComposition =
                            (Z_RecordComposition *)
                            odr_malloc(m_s2z_odr_search,
                                       sizeof(Z_RecordComposition));
                        z_presentRequest->recordComposition->which =
                            Z_RecordComp_simple;
                        z_presentRequest->recordComposition->u.simple =
                            mk_esn_from_schema(m_s2z_odr_search,
                                               srw_req->recordSchema);
                    }
                }
            }
            if (!m_client)
            {
                m_s2z_init_apdu = zget_APDU(m_s2z_odr_init,
                                            Z_APDU_initRequest);

                m_s2z_init_apdu->u.initRequest->idAuthentication = auth;

                // prevent m_initRequest_apdu memory from being grabbed
                // in Yaz_Proxy::handle_incoming_Z_PDU
                m_initRequest_apdu = m_s2z_init_apdu;
                handle_incoming_Z_PDU(m_s2z_init_apdu);
                return;
            }
            else
            {
                handle_incoming_Z_PDU(m_s2z_search_apdu);
                return;
            }
        }
        else if (srw_pdu->which == Z_SRW_explain_request)
        {
            Z_SRW_explainRequest *srw_req = srw_pdu->u.explain_request;

            const char *backend_db = srw_req->database;
            srw_get_client(srw_req->database, &backend_db);

            m_s2z_database = odr_strdup(m_s2z_odr_init, srw_req->database);

            // save stylesheet
            if (srw_req->stylesheet)
                m_s2z_stylesheet =
                    odr_strdup(m_s2z_odr_init, srw_req->stylesheet);

            if (srw_req->recordPacking &&
                !strcmp(srw_req->recordPacking, "xml"))
                m_s2z_packing = Z_SRW_recordPacking_XML;
            else
                m_s2z_packing = Z_SRW_recordPacking_string;

            if (num_diagnostic)
            {
                send_srw_explain_response(diagnostic, num_diagnostic);
                return;
            }

            if (!m_client)
            {
                m_s2z_init_apdu = zget_APDU(m_s2z_odr_init,
                                            Z_APDU_initRequest);

                m_s2z_init_apdu->u.initRequest->idAuthentication = auth;
                
                // prevent m_initRequest_apdu memory from being grabbed
                // in Yaz_Proxy::handle_incoming_Z_PDU
                m_initRequest_apdu = m_s2z_init_apdu;
                handle_incoming_Z_PDU(m_s2z_init_apdu);
            }
            else
                send_srw_explain_response(0, 0);
            return;
        }
        else if (srw_pdu->which == Z_SRW_scan_request)
        {
            m_s2z_database = odr_strdup(m_s2z_odr_init,
                                        srw_pdu->u.scan_request->database);

            yaz_add_srw_diagnostic(odr_decode(),
                                   &diagnostic, &num_diagnostic,
                                   4, "scan");
            Z_SRW_PDU *srw_pdu =
                yaz_srw_get(odr_encode(),
                            Z_SRW_scan_response);
            Z_SRW_scanResponse *srw_res = srw_pdu->u.scan_response;

            srw_res->diagnostics = diagnostic;
            srw_res->num_diagnostics = num_diagnostic;
            send_srw_response(srw_pdu);
            return;
        }
        else
        {
            m_s2z_database = 0;

            send_to_srw_client_error(4, 0);
        }
    }
    send_http_response(400);
}

void Yaz_Proxy::handle_init(Z_APDU *apdu)
{

    Z_OtherInformation **oi;
    get_otherInfoAPDU(apdu, &oi);

    if (apdu->u.initRequest->implementationId)
        yaz_log(YLOG_LOG, "%simplementationId: %s",
                m_session_str, apdu->u.initRequest->implementationId);
    if (apdu->u.initRequest->implementationName)
        yaz_log(YLOG_LOG, "%simplementationName: %s",
                m_session_str, apdu->u.initRequest->implementationName);
    if (apdu->u.initRequest->implementationVersion)
        yaz_log(YLOG_LOG, "%simplementationVersion: %s",
                m_session_str, apdu->u.initRequest->implementationVersion);
    if (m_initRequest_apdu == 0)
    {
        if (m_initRequest_mem)
            nmem_destroy(m_initRequest_mem);

        m_initRequest_apdu = apdu;
        m_initRequest_mem = odr_extract_mem(odr_decode());

        m_initRequest_preferredMessageSize = *apdu->u.initRequest->
            preferredMessageSize;
        *apdu->u.initRequest->preferredMessageSize = 1024*1024;
        m_initRequest_maximumRecordSize = *apdu->u.initRequest->
            maximumRecordSize;
        *apdu->u.initRequest->maximumRecordSize = 1024*1024;

        Z_CharSetandLanguageNegotiation *charSetandLangRecord =
            yaz_get_charneg_record(*oi);

        // Save proposal charsets and langs.
        if (ODR_MASK_GET(apdu->u.initRequest->options,
                         Z_Options_negotiationModel)
            && charSetandLangRecord)
        {

            yaz_get_proposal_charneg(m_referenceId_mem,
                                     charSetandLangRecord,
                                     &m_initRequest_oi_negotiation_charsets,
                                     &m_initRequest_oi_negotiation_num_charsets,
                                     &m_initRequest_oi_negotiation_langs,
                                     &m_initRequest_oi_negotiation_num_langs,
                                     &m_initRequest_oi_negotiation_selected);

            for (int i = 0; i<m_initRequest_oi_negotiation_num_charsets; i++)
            {
                yaz_log(YLOG_LOG, "%scharacters set proposal: %s",
                        m_session_str,(m_initRequest_oi_negotiation_charsets[i])?
                        m_initRequest_oi_negotiation_charsets[i]:"none");
            }
            for (int i=0; i<m_initRequest_oi_negotiation_num_langs; i++)
            {
                yaz_log(YLOG_LOG, "%slanguages proposal: %s",
                        m_session_str, (m_initRequest_oi_negotiation_langs[i])?
                        m_initRequest_oi_negotiation_langs[i]:"none");
            }
            yaz_log(YLOG_LOG, "%sselected proposal: %d (boolean)",
                    m_session_str, m_initRequest_oi_negotiation_selected);
        }
        // save init options for the response..
        m_initRequest_options = apdu->u.initRequest->options;

        apdu->u.initRequest->options =
            (Odr_bitmask *)nmem_malloc(m_initRequest_mem,
                                       sizeof(Odr_bitmask));
        ODR_MASK_ZERO(apdu->u.initRequest->options);
        int i;
        for (i = 0; i<= 24; i++)
            ODR_MASK_SET(apdu->u.initRequest->options, i);
        // check negotiation option
        if (!ODR_MASK_GET(m_initRequest_options,
                          Z_Options_negotiationModel))
        {
            ODR_MASK_CLEAR(apdu->u.initRequest->options,
                           Z_Options_negotiationModel);
        }
        ODR_MASK_CLEAR(apdu->u.initRequest->options,
                       Z_Options_concurrentOperations);
        // make new version
        m_initRequest_version = apdu->u.initRequest->protocolVersion;
        apdu->u.initRequest->protocolVersion =
            (Odr_bitmask *)nmem_malloc(m_initRequest_mem,
                                       sizeof(Odr_bitmask));
        ODR_MASK_ZERO(apdu->u.initRequest->protocolVersion);

        for (i = 0; i<= 8; i++)
            ODR_MASK_SET(apdu->u.initRequest->protocolVersion, i);
    }
    handle_charset_lang_negotiation(apdu);
    if (m_client->m_init_flag)
    {
        if (handle_init_response_for_invalid_session(apdu))
            return;
        if (m_client->m_initResponse)
        {
            Z_APDU *apdu2 = m_client->m_initResponse;
            apdu2->u.initResponse->otherInfo = 0;
            if (m_client->m_cookie && *m_client->m_cookie)
                set_otherInformationString(apdu2, VAL_COOKIE, 1,
                                           m_client->m_cookie);
            apdu2->u.initResponse->referenceId =
                apdu->u.initRequest->referenceId;
            apdu2->u.initResponse->options = m_client->m_initResponse_options;
            apdu2->u.initResponse->protocolVersion =
                m_client->m_initResponse_version;

            handle_charset_lang_negotiation(apdu2);

	    if (m_timeout_mode == timeout_busy)
	        m_timeout_mode = timeout_normal;
            send_to_client(apdu2);
            return;
        }
    }
    m_client->m_init_flag = 1;

    if (m_num_msg_threads && m_my_thread)
    {
        Auth_Msg *m = new Auth_Msg;
        m->m_proxy = this;
        z_APDU(odr_encode(), &apdu, 0, "encode");
        char *apdu_buf = odr_getbuf(odr_encode(), &m->m_apdu_len, 0);
        m->m_apdu_buf = (char*) nmem_malloc(m->m_nmem, m->m_apdu_len);
        memcpy(m->m_apdu_buf, apdu_buf, m->m_apdu_len);
        odr_reset(odr_encode());
        
        inc_ref();
        m_my_thread->put(m);
    }
    else
    {
        int ret = handle_authentication(apdu);
        result_authentication(apdu, ret);
    }
}

void Yaz_Proxy::handle_incoming_Z_PDU(Z_APDU *apdu)
{
    Z_ReferenceId **refid = get_referenceIdP(apdu);
    nmem_reset(m_referenceId_mem);
    if (refid && *refid)
    {
        m_referenceId = (Z_ReferenceId *)
            nmem_malloc(m_referenceId_mem, sizeof(*m_referenceId));
        m_referenceId->len = m_referenceId->size = (*refid)->len;
        m_referenceId->buf = (unsigned char *)
            nmem_malloc(m_referenceId_mem, (*refid)->len);
        memcpy(m_referenceId->buf, (*refid)->buf, (*refid)->len);
    }
    else
        m_referenceId = 0;

    if (!m_client && m_flag_invalid_session)
    {
        // Got request for a session that is invalid..
        m_apdu_invalid_session = apdu; // save package
        m_mem_invalid_session = odr_extract_mem(odr_decode());
        apdu = m_initRequest_apdu;     // but throw an init to the target
    }

    if (apdu->which == Z_APDU_searchRequest)
        m_search_stat.add_bytes(1);

    // Handle global authentication
    if (!handle_global_authentication(apdu))
    {
        if (m_http_version)
        {   // HTTP. Send unauthorized
            send_http_response(401);
            return;
        }
        else
        {
            // Z39.50 just shutdown
            timeout(0);
            return;
        }
        return;
    }

    // Determine our client.
    Z_OtherInformation **oi;
    get_otherInfoAPDU(apdu, &oi);
    m_client = get_client(apdu, get_cookie(oi), get_proxy(oi));
    if (!m_client)
    {
        if (m_http_version)
        {   // HTTP. Send not found
            send_http_response(404);
            return;
        }
        else
        {
            // Z39.50 just shutdown
            timeout(0);
            return;
        }
    }

    m_client->m_server = this;

    if (apdu->which == Z_APDU_initRequest)
        handle_init(apdu);
    else
        handle_incoming_Z_PDU_2(apdu);
}

void Yaz_Proxy::handle_incoming_Z_PDU_2(Z_APDU *apdu)
{
    handle_max_record_retrieve(apdu);

    if (apdu)
        apdu = handle_syntax_validation(apdu);

    if (apdu)
        apdu = handle_query_transformation(apdu);

    if (apdu)
        apdu = handle_target_charset_conversion(apdu);

    if (apdu)
        apdu = handle_query_validation(apdu);

    if (apdu)
        apdu = result_set_optimize(apdu);

    if (!apdu)
    {
        m_client->timeout(m_target_idletime);  // mark it active even
        recv_GDU_more(true);
        // though we didn't use it
        return;
    }

    // delete other info construct completely if 0 elements
    Z_OtherInformation **oi;
    get_otherInfoAPDU(apdu, &oi);
    if (oi && *oi && (*oi)->num_elements == 0)
        *oi = 0;

    if (apdu->which == Z_APDU_presentRequest &&
        m_client->m_resultSetStartPoint == 0)
    {
        Z_PresentRequest *pr = apdu->u.presentRequest;
        m_client->m_resultSetStartPoint = *pr->resultSetStartPoint;
        m_client->m_cache.copy_presentRequest(apdu->u.presentRequest);
    } else {
        m_client->m_resultSetStartPoint = 0;
    }
    if (m_client->send_to_target(apdu) < 0)
    {
        m_client->shutdown();
    }
    else
        m_client->m_waiting = 1;
}

void Yaz_Proxy::connectNotify()
{
}

void Yaz_Proxy::releaseClient()
{
    xfree(m_proxyTarget);
    m_proxyTarget = 0;
    m_flag_invalid_session = 0;
    // only keep if keep_alive flag is set...
    if (m_client &&
        m_client->m_pdu_recv < m_keepalive_limit_pdu &&
        m_client->m_bytes_recv+m_client->m_bytes_sent < m_keepalive_limit_bw &&
        m_client->m_waiting == 0)
    {
        yaz_log(YLOG_LOG, "%sShutdown (client to proxy) keepalive %s",
                 m_session_str,
                 m_client->get_hostname());
        yaz_log(YLOG_LOG, "%sbw=%d pdu=%d limit-bw=%d limit-pdu=%d",
                m_session_str, m_client->m_pdu_recv,
                m_client->m_bytes_sent + m_client->m_bytes_recv,
                m_keepalive_limit_bw, m_keepalive_limit_pdu);
        assert (m_client->m_waiting != 2);
        // Tell client (if any) that no server connection is there..
        m_client->m_server = 0;
        m_client = 0;
    }
    else if (m_client)
    {
        yaz_log (YLOG_LOG, "%sShutdown (client to proxy) close %s",
                 m_session_str,
                 m_client->get_hostname());
        assert (m_client->m_waiting != 2);
        delete m_client;
        m_client = 0;
    }
    else if (!m_parent)
    {
        yaz_log (YLOG_LOG, "%sshutdown (client to proxy) bad state",
                 m_session_str);
        assert (m_parent);
    }
    else
    {
        yaz_log (YLOG_LOG, "%sShutdown (client to proxy)",
                 m_session_str);
    }
    if (m_parent)
        m_parent->pre_init();
}

bool Yaz_Proxy::dec_ref()
{
    m_http_keepalive = 0;

    --m_ref_count;
    if (m_ref_count > 0)
        return false;

    releaseClient();

    delete this;
    return true;
}

const char *Yaz_ProxyClient::get_session_str()
{
    if (!m_server)
        return "0 ";
    return m_server->get_session_str();
}

void Yaz_ProxyClient::shutdown()
{
    yaz_log (YLOG_LOG, "%sShutdown (proxy to target) %s", get_session_str(),
             get_hostname());

    if (m_server)
    {
        m_waiting = 1;   // ensure it's released from Yaz_Proxy::releaseClient
        m_server->dec_ref();
    }
    else
        delete this;
}

void Yaz_Proxy::failNotify()
{
    inc_request_no();
    yaz_log (YLOG_LOG, "%sConnection closed by client", get_session_str());
    dec_ref();
}

void Yaz_Proxy::send_response_fail_client(const char *addr)
{
    if (m_http_version)
    {
        Z_SRW_diagnostic *diagnostic = 0;
        int num_diagnostic = 0;
        
        yaz_add_srw_diagnostic(odr_encode(),
                               &diagnostic, &num_diagnostic,
                               YAZ_SRW_SYSTEM_TEMPORARILY_UNAVAILABLE, addr);
        if (m_s2z_search_apdu)
            send_srw_search_response(diagnostic, num_diagnostic);
        else
            send_srw_explain_response(diagnostic, num_diagnostic);
    }            
}
void Yaz_ProxyClient::failNotify()
{
    if (m_server)
        m_server->inc_request_no();
    yaz_log (YLOG_LOG, "%sConnection closed by target %s",
             get_session_str(), get_hostname());

    if (m_server)
        m_server->send_response_fail_client(get_hostname());
    shutdown();
}

void Yaz_ProxyClient::connectNotify()
{
    const char *s = get_session_str();
    const char *h = get_hostname();
    yaz_log (YLOG_LOG, "%sConnection accepted by %s timeout=%d", s, h,
             m_target_idletime);
    timeout(m_target_idletime);
    if (!m_server)
        pre_init_client();
}

IPDU_Observer *Yaz_ProxyClient::sessionNotify(IPDU_Observable
                                              *the_PDU_Observable, int fd)
{
    return new Yaz_ProxyClient(the_PDU_Observable, 0);
}

Yaz_ProxyClient::~Yaz_ProxyClient()
{
    if (m_prev)
        *m_prev = m_next;
    if (m_next)
        m_next->m_prev = m_prev;
    m_waiting = 2;     // for debugging purposes only.
    odr_destroy(m_init_odr);
    odr_destroy(m_idAuthentication_odr);
    delete m_last_query;
    xfree (m_last_resultSetId);
    xfree (m_cookie);
}

void Yaz_ProxyClient::pre_init_client()
{
    Z_APDU *apdu = create_Z_PDU(Z_APDU_initRequest);
    Z_InitRequest *req = apdu->u.initRequest;

    int i;
    for (i = 0; i<= 24; i++)
        ODR_MASK_SET(req->options, i);
    ODR_MASK_CLEAR(apdu->u.initRequest->options,
                   Z_Options_negotiationModel);
    ODR_MASK_CLEAR(apdu->u.initRequest->options,
                   Z_Options_concurrentOperations);
    for (i = 0; i<= 10; i++)
        ODR_MASK_SET(req->protocolVersion, i);

    if (send_to_target(apdu) < 0)
    {
        delete this;
    }
    else
    {
        m_waiting = 1;
        m_init_flag = 1;
    }
}

void Yaz_Proxy::pre_init()
{
    int i;
    const char *name = 0;
    const char *zurl_in_use[MAX_ZURL_PLEX];
    int limit_bw, limit_pdu, limit_req, limit_search;
    int target_idletime, client_idletime;
    int max_clients;
    int keepalive_limit_bw, keepalive_limit_pdu;
    int pre_init;
    const char *cql2rpn = 0;
    const char *authentication = 0;
    const char *negotiation_charset = 0;
    const char *negotiation_lang = 0;

    Yaz_ProxyConfig *cfg = check_reconfigure();

    zurl_in_use[0] = 0;

    if (m_log_mask & PROXY_LOG_APDU_CLIENT)
        set_APDU_yazlog(1);
    else
        set_APDU_yazlog(0);

    for (i = 0; cfg && cfg->get_target_no(i, &name, zurl_in_use,
                                          &limit_bw, &limit_pdu, &limit_req,
                                          &limit_search,
                                          &target_idletime, &client_idletime,
                                          &max_clients,
                                          &keepalive_limit_bw,
                                          &keepalive_limit_pdu,
                                          &pre_init,
                                          &cql2rpn,
                                          &authentication,
                                          &negotiation_charset,
                                          &negotiation_lang,
                                          0,
                                          0) ; i++)
    {
        if (pre_init)
        {
            int j;
            for (j = 0; zurl_in_use[j]; j++)
            {
                Yaz_ProxyClient *c;
                int spare = 0;
                int spare_waiting = 0;
                int in_use = 0;
                int other = 0;
                for (c = m_clientPool; c; c = c->m_next)
                {
                    if (!strcmp(zurl_in_use[j], c->get_hostname()))
                    {
                        if (c->m_cookie == 0)
                        {
                            if (c->m_server == 0)
                                if (c->m_waiting)
                                    spare_waiting++;
                                else
                                    spare++;
                            else
                                in_use++;
                        }
                        else
                            other++;
                    }
                }
                yaz_log(YLOG_LOG, "%spre-init %s %s use=%d other=%d spare=%d "
                        "sparew=%d preinit=%d",m_session_str,
                        name, zurl_in_use[j], in_use, other,
                        spare, spare_waiting, pre_init);
                if (spare + spare_waiting < pre_init)
                {
                    c = new Yaz_ProxyClient(m_PDU_Observable->clone(), this);
                    c->m_next = m_clientPool;
                    if (c->m_next)
                        c->m_next->m_prev = &c->m_next;
                    m_clientPool = c;
                    c->m_prev = &m_clientPool;

                    if (m_log_mask & PROXY_LOG_APDU_SERVER)
                        c->set_APDU_yazlog(1);
                    else
                        c->set_APDU_yazlog(0);

                    if (c->client(zurl_in_use[j]))
                    {
                        timeout(60);
                        delete c;
                        return;
                    }
                    c->timeout(30);
                    c->m_waiting = 1;
                    c->m_target_idletime = target_idletime;
                    c->m_seqno = m_seqno++;
                }
            }
        }
    }
}

void Yaz_Proxy::timeoutNotify()
{
    if (m_parent)
    {
        GDU *gdu;
        switch(m_timeout_mode)
        {
        case timeout_normal:
        case timeout_busy:
            inc_request_no();
            m_in_queue.clear();
            yaz_log (YLOG_LOG, "%sTimeout (client to proxy)", m_session_str);
            dec_ref();
            break;
        case timeout_reduce:
            timeout(m_client_idletime);
            m_timeout_mode = timeout_busy;
            gdu = m_timeout_gdu;
            m_timeout_gdu = 0;
            recv_GDU_normal(gdu);
            break;
        case timeout_xsl:
            assert(m_stylesheet_nprl);
            convert_xsl_delay();
            recv_GDU_more(true);
        }
    }
    else
    {
        timeout(600);
        pre_init();
    }
}

void Yaz_Proxy::markInvalid()
{
    m_client = 0;
    m_flag_invalid_session = 1;
}

void Yaz_ProxyClient::timeoutNotify()
{
    if (m_server)
        m_server->inc_request_no();

    yaz_log (YLOG_LOG, "%sTimeout (proxy to target) %s", get_session_str(),
             get_hostname());

    if (m_server)
        m_server->send_response_fail_client(get_hostname());

    Yaz_Proxy *proxy_root = m_root;

    shutdown();

    proxy_root->pre_init();
}

Yaz_ProxyClient::Yaz_ProxyClient(IPDU_Observable *the_PDU_Observable,
                                 Yaz_Proxy *parent) :
    Z_Assoc (the_PDU_Observable)
{
    m_cookie = 0;
    m_next = 0;
    m_prev = 0;
    m_init_flag = 0;
    m_last_query = 0;
    m_last_resultSetId = 0;
    m_last_resultCount = 0;
    m_last_ok = 0;
    m_sr_transform = 0;
    m_waiting = 0;
    m_init_odr = odr_createmem (ODR_DECODE);
    m_initResponse = 0;
    m_initResponse_options = 0;
    m_initResponse_version = 0;
    m_initResponse_preferredMessageSize = 0;
    m_initResponse_maximumRecordSize = 0;
    m_resultSetStartPoint = 0;
    m_bytes_sent = m_bytes_recv = 0;
    m_pdu_recv = 0;
    m_server = 0;
    m_seqno = 0;
    m_target_idletime = 600;
    m_root = parent;
    m_idAuthentication_odr = odr_createmem(ODR_ENCODE);
    m_idAuthentication_ber_buf = 0;
    m_idAuthentication_ber_size = 0;
}

const char *Yaz_Proxy::option(const char *name, const char *value)
{
    if (!strcmp (name, "optimize")) {
        if (value) {
            xfree (m_optimize);
            m_optimize = xstrdup (value);
        }
        return m_optimize;
    }
    return 0;
}

void Yaz_ProxyClient::recv_HTTP_response(Z_HTTP_Response *apdu, int len)
{

}

void Yaz_ProxyClient::recv_GDU(Z_GDU *apdu, int len)
{
    if (apdu->which == Z_GDU_Z3950)
        recv_Z_PDU(apdu->u.z3950, len);
    else if (apdu->which == Z_GDU_HTTP_Response)
        recv_HTTP_response(apdu->u.HTTP_Response, len);
    else
        shutdown();
}

int Yaz_Proxy::handle_init_response_for_invalid_session(Z_APDU *apdu)
{
    if (!m_flag_invalid_session)
        return 0;
    m_flag_invalid_session = 0;
    handle_incoming_Z_PDU(m_apdu_invalid_session);
    assert (m_mem_invalid_session);
    nmem_destroy(m_mem_invalid_session);
    m_mem_invalid_session = 0;
    return 1;
}

void Yaz_ProxyClient::recv_Z_PDU(Z_APDU *apdu, int len)
{
    m_bytes_recv += len;

    m_pdu_recv++;
    m_waiting = 0;
    if (m_root->get_log_mask() & PROXY_LOG_REQ_SERVER)
        yaz_log (YLOG_LOG, "%sReceiving %s from %s %d bytes", get_session_str(),
                 apdu_name(apdu), get_hostname(), len);
    if (apdu->which == Z_APDU_initResponse)
    {
        if (!m_server)  // if this is a pre init session , check for more
            m_root->pre_init();
        NMEM nmem = odr_extract_mem (odr_decode());
        odr_reset (m_init_odr);
        nmem_transfer (m_init_odr->mem, nmem);
        m_initResponse = apdu;
        m_initResponse_options = apdu->u.initResponse->options;
        m_initResponse_version = apdu->u.initResponse->protocolVersion;
        m_initResponse_preferredMessageSize =
            *apdu->u.initResponse->preferredMessageSize;
        m_initResponse_maximumRecordSize =
            *apdu->u.initResponse->maximumRecordSize;

        Z_InitResponse *ir = apdu->u.initResponse;
       
        // apply YAZ Proxy version
        char *imv0 = ir->implementationVersion;
        char *imv1 = (char*)
            odr_malloc(m_init_odr, 20 + (imv0 ? strlen(imv0) : 0));
        *imv1 = '\0';
        if (imv0)
            strcat(imv1, imv0);
#ifdef VERSION
        strcat(imv1, "/" VERSION);
#endif
        ir->implementationVersion = imv1;
        
        // apply YAZ Proxy implementation name
        char *im0 = ir->implementationName;
        char *im1 = (char*)
            odr_malloc(m_init_odr, 20 + (im0 ? strlen(im0) : 0));
        *im1 = '\0';
        if (im0)
        {
            strcat(im1, im0);
            strcat(im1, " ");
        }
        strcat(im1, "(YAZ Proxy)");
        ir->implementationName = im1;

        nmem_destroy (nmem);

        if (m_server && m_server->handle_init_response_for_invalid_session(apdu))
            return;
    }
    if (apdu->which == Z_APDU_searchResponse)
    {
        Z_SearchResponse *sr = apdu->u.searchResponse;
        m_last_resultCount = *sr->resultCount;
        int status = *sr->searchStatus;
        if (status && (!sr->records || sr->records->which == Z_Records_DBOSD))
        {
            m_last_ok = 1;

            if (sr->records && sr->records->which == Z_Records_DBOSD)
            {
                m_cache.add(odr_decode(),
                            sr->records->u.databaseOrSurDiagnostics, 1,
                            *sr->resultCount);
            }
        }
    }
    if (apdu->which == Z_APDU_presentResponse)
    {
        Z_PresentResponse *pr = apdu->u.presentResponse;
        if (m_sr_transform)
        {
            m_sr_transform = 0;
            Z_APDU *new_apdu = create_Z_PDU(Z_APDU_searchResponse);
            Z_SearchResponse *sr = new_apdu->u.searchResponse;
            sr->referenceId = pr->referenceId;
            *sr->resultCount = m_last_resultCount;
            sr->records = pr->records;
            sr->nextResultSetPosition = pr->nextResultSetPosition;
            sr->numberOfRecordsReturned = pr->numberOfRecordsReturned;
            apdu = new_apdu;
        }
        if (pr->records &&
            pr->records->which == Z_Records_DBOSD && m_resultSetStartPoint)
        {
            m_cache.add(odr_decode(),
                        pr->records->u.databaseOrSurDiagnostics,
                        m_resultSetStartPoint, -1);
            m_resultSetStartPoint = 0;
        }
    }
    if (m_cookie)
        set_otherInformationString (apdu, VAL_COOKIE, 1, m_cookie);

    Yaz_Proxy *server = m_server; // save it. send_to_client may destroy us

    if (server)
        server->send_to_client(apdu);
    if (apdu->which == Z_APDU_close)
        shutdown();
    else if (server)
        server->recv_GDU_more(true);
}

void Yaz_Proxy::low_socket_close()
{
#if WIN32
#else
    int i;
    for (i = 0; i<NO_SPARE_SOLARIS_FD; i++)
        if  (m_lo_fd[i] >= 0)
            ::close(m_lo_fd[i]);
#endif
}

void Yaz_Proxy::low_socket_open()
{
#if WIN32
#else
    int i;
    for (i = 0; i<NO_SPARE_SOLARIS_FD; i++)
        m_lo_fd[i] = open("/dev/null", O_RDONLY);
#endif
}

int Yaz_Proxy::server(const char *addr)
{
    int r = Z_Assoc::server(addr);
    if (!r)
    {
        yaz_log(YLOG_LOG, "%sStarted proxy "
#ifdef VERSION
            VERSION
#endif
            " on %s", m_session_str, addr);
        timeout(1);
    }
    return r;
}

void Yaz_Proxy::base64_decode(const char *base64, char *buf, int buf_len)
{
    const char *base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = strlen(base64);
    int buf_pos = 0;
    int index = 1;

    for (int pos = 0; pos <= len; pos++)
    {
        if (base64[pos] == '=' || buf_pos + 1 >= buf_len)
            break;

        const char *ch_ptr = strchr(base64_chars, base64[pos]);
        if (!ch_ptr)
            break;
        char ch = (char) (ch_ptr - base64_chars);
        switch (index)
        {
            case 1:
                buf[buf_pos] = ch << 2;
                break;
            case 2:
                buf[buf_pos++] += (ch & 0x30) >> 4;
                buf[buf_pos] = (ch & 0x0f) << 4;
                break;
            case 3:
                buf[buf_pos++] += (ch & 0x3c) >> 2;
                buf[buf_pos] = (ch & 0x03) << 6;
                break;
            case 4:
                buf[buf_pos++] += ch;
        }
        if (index < 4)
            index++;
        else
            index = 1;
    }
    buf[buf_pos] = '\0';
}

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

