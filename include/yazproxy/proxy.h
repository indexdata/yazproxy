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

#ifndef YAZ_PROXY_H_INCLUDED
#define YAZ_PROXY_H_INCLUDED

#include <yazpp/socket-observer.h>
#include <yazpp/z-assoc.h>
#include <yazpp/z-query.h>
#include <yazpp/z-databases.h>
#include <yazpp/cql2rpn.h>
#include <yaz/cql.h>
#include <yazpp/gdu.h>
#include <yazpp/gduqueue.h>
#include <yazproxy/bw.h>
#include <yazproxy/limit-connect.h>

class Yaz_Proxy;

#define MAX_ZURL_PLEX 10

#define PROXY_LOG_APDU_CLIENT 1
#define PROXY_LOG_APDU_SERVER 2
#define PROXY_LOG_REQ_CLIENT 4
#define PROXY_LOG_REQ_SERVER 8
#define PROXY_LOG_IP_CLIENT 16

class Yaz_usemarcon;
class Yaz_ProxyConfig;
class Yaz_ProxyClient;
class Yaz_CharsetConverter;

enum YAZ_Proxy_MARCXML_mode {
    none,
    marcxml
};

class Msg_Thread;

/// Information Retrieval Proxy Server.
class YAZ_EXPORT Yaz_Proxy : public yazpp_1::Z_Assoc {
    friend class Proxy_Msg;
 private:
    char *m_peername;
    int m_ref_count;
    bool m_main_ptr_dec;
    char *get_cookie(Z_OtherInformation **otherInfo);
    char *get_proxy(Z_OtherInformation **otherInfo);
    void get_charset_and_lang_negotiation(Z_OtherInformation **otherInfo,
        char **charstes, char **langs, int *selected);
    void HTTP_Forwarded(Z_GDU *z_gdu);
    void connect_stat(bool &block, int &reduce);
    Yaz_ProxyClient *get_client(Z_APDU *apdu, const char *cookie,
                                const char *proxy_host, int *http_code);
    void srw_get_client(const char *db, const char **backend_db);
    int get_number_of_connections();
    Z_APDU *result_set_optimize(Z_APDU *apdu);
    void releaseClient();
    Yaz_ProxyClient *m_client;
    yazpp_1::IPDU_Observable *m_PDU_Observable;
    yazpp_1::ISocketObservable *m_socket_observable;
    Yaz_ProxyClient *m_clientPool;
    Yaz_Proxy *m_parent;
    int m_seqno;
    int m_max_clients;
    int m_log_mask;
    int m_keepalive_limit_bw;
    int m_keepalive_limit_pdu;
    int m_client_idletime;
    int m_target_idletime;
    int m_max_sockets;
    int m_debug_mode;
    char *m_proxyTarget;
    char *m_default_target;
    char *m_proxy_negotiation_charset;
    char *m_proxy_negotiation_lang;
    char *m_proxy_negotiation_default_charset;
    long m_seed;
    char *m_optimize;
    int m_session_no;         // sequence for each client session
    char m_session_str[200];  // session string (time:session_no)
    Yaz_ProxyConfig *m_config;
    char *m_config_fname;
    int m_bytes_sent;
    int m_bytes_recv;
    int m_bw_max;

    yazpp_1::GDU *m_timeout_gdu;
    enum timeout_mode {
        timeout_busy,
        timeout_normal,
        timeout_reduce,
        timeout_xsl
    } m_timeout_mode;

    int m_max_connect;
    int m_max_connect_period;
    int m_limit_connect;
    int m_limit_connect_period;
    int m_search_max;
    Yaz_bw m_bw_stat;
    int m_pdu_max;
    Yaz_bw m_pdu_stat;
    int m_max_record_retrieve;
    Yaz_bw m_search_stat;

    void handle_max_record_retrieve(Z_APDU *apdu);
    void display_diagrecs(Z_DiagRec **pp, int num);
    Z_Records *create_nonSurrogateDiagnostics(ODR o, int error,
                                              const char *addinfo);
    Z_ListEntries *create_nonSurrogateDiagnostics2(ODR o, int error,
                                              const char *addinfo);

    Z_APDU *handle_query_validation(Z_APDU *apdu);
    Z_APDU *handle_query_transformation(Z_APDU *apdu);
    Z_APDU *handle_target_charset_conversion(Z_APDU *apdu);

    Z_APDU *handle_syntax_validation(Z_APDU *apdu);
    Z_APDU *handle_database_validation(Z_APDU *apdu);

    void handle_charset_lang_negotiation(Z_APDU *apdu);

    const char *load_balance(const char **url);
    int m_reconfig_flag;
    Yaz_ProxyConfig *check_reconfigure();
    int m_request_no;
    int m_flag_invalid_session;
    YAZ_Proxy_MARCXML_mode m_marcxml_mode;
    void *m_stylesheet_xsp;  // Really libxslt's xsltStylesheetPtr
    int m_stylesheet_offset;
    Z_APDU *m_stylesheet_apdu;
    Z_NamePlusRecordList *m_stylesheet_nprl;
    char *m_schema;
    char *m_backend_type;
    char *m_backend_charset;
    Odr_oid m_frontend_type[OID_SIZE];
    void convert_to_frontend_type(Z_NamePlusRecordList *p);
    void convert_to_marcxml(Z_NamePlusRecordList *p, const char *charset);
    void convert_records_charset(Z_NamePlusRecordList *p, const char *charset);
    int convert_xsl(Z_NamePlusRecordList *p, Z_APDU *apdu);
    void convert_xsl_delay();
    Z_APDU *m_initRequest_apdu;
    int m_initRequest_preferredMessageSize;
    int m_initRequest_maximumRecordSize;
    Z_Options *m_initRequest_options;
    Z_ProtocolVersion *m_initRequest_version;
    char **m_initRequest_oi_negotiation_charsets;
    int m_initRequest_oi_negotiation_num_charsets;
    char **m_initRequest_oi_negotiation_langs;
    int m_initRequest_oi_negotiation_num_langs;
    int m_initRequest_oi_negotiation_selected;
    NMEM m_initRequest_mem;
    Z_APDU *m_apdu_invalid_session;
    NMEM m_mem_invalid_session;
    int send_PDU_convert(Z_APDU *apdu);
    ODR m_s2z_odr_init;
    ODR m_s2z_odr_search;
    ODR m_s2z_odr_scan;
    int m_s2z_hit_count;
    int m_s2z_packing;
    char *m_s2z_database;
    Z_APDU *m_s2z_init_apdu;
    Z_APDU *m_s2z_search_apdu;
    Z_APDU *m_s2z_present_apdu;
    Z_APDU *m_s2z_scan_apdu;
    char *m_s2z_stylesheet;
    char *m_soap_ns;
    int file_access(Z_HTTP_Request *hreq);
    int send_to_srw_client_error(int error, const char *add);
    int send_to_srw_client_ok(int hits, Z_Records *records, int start);
    int send_to_srw_client_ok(Z_ListEntries *entries);
    int send_http_response(int code);
    int send_srw_response(Z_SRW_PDU *srw_pdu, int http_code = 200);
    int send_srw_search_response(Z_SRW_diagnostic *diagnostics,
                                 int num_diagnostics,
                                 int http_code = 200);
    int send_srw_scan_response(Z_SRW_diagnostic *diagnostics,
                                 int num_diagnostics,
                                 int http_code = 200);
    int send_srw_explain_response(Z_SRW_diagnostic *diagnostics,
                                  int num_diagnostics);
    int z_to_srw_diag(ODR o, Z_SRW_searchRetrieveResponse *srw_res,
                      Z_DefaultDiagFormat *ddf);
    int z_to_srw_diag(ODR o, Z_SRW_scanResponse *srw_res,
                      Z_DiagRec *dr);
    int m_http_keepalive;
    const char *m_http_version;
    const char *m_sru_version;
    yazpp_1::Yaz_cql2rpn m_cql2rpn;
    void *m_time_tv;
    void logtime();
    Z_ElementSetNames *mk_esn_from_schema(ODR o, const char *schema);
    Z_ReferenceId *m_referenceId;
    NMEM m_referenceId_mem;

#define NO_SPARE_SOLARIS_FD 10
    int m_lo_fd[NO_SPARE_SOLARIS_FD];
    void low_socket_open();
    void low_socket_close();
    char *m_usemarcon_ini_stage1;
    char *m_usemarcon_ini_stage2;
    char *m_backend_elementset;
    Yaz_usemarcon *m_usemarcon;
    Yaz_CharsetConverter *m_charset_converter;
    yazpp_1::GDUQueue m_in_queue;
    LimitConnect m_connect;
 public:
    Yaz_Proxy(yazpp_1::IPDU_Observable *the_PDU_Observable,
              yazpp_1::ISocketObservable *the_socket_observable,
              Yaz_Proxy *parent = 0);
    ~Yaz_Proxy();

    void inc_ref();
    bool dec_ref();

    int handle_authentication(Z_APDU *apdu);
    int handle_global_authentication(Z_APDU *apdu);
    void result_authentication(Z_APDU *apdu, int ret);
    void handle_init(Z_APDU *apdu);
    void inc_request_no();
    void recv_GDU(Z_GDU *apdu, int len);
    void recv_GDU_reduce(yazpp_1::GDU *gdu);
    void recv_GDU_normal(yazpp_1::GDU *gdu);
    void recv_GDU_more(bool normal);
    void handle_incoming_HTTP(Z_HTTP_Request *req);
    void handle_incoming_Z_PDU(Z_APDU *apdu);
    void handle_incoming_Z_PDU_2(Z_APDU *apdu);
    IPDU_Observer *sessionNotify(yazpp_1::IPDU_Observable *the_PDU_Observable,
                                 int fd);
    void failNotify();
    void timeoutNotify();
    void connectNotify();
    void markInvalid();
    const char *option(const char *name, const char *value);
    void set_default_target(const char *target);
    void set_proxy_negotiation(const char *charset, const char *lang,
                               const char *default_charset);
    void set_target_charset(const char *charset);
    char *get_proxy_target() { return m_proxyTarget; };
    char *get_session_str() { return m_session_str; };
    void set_max_clients(int m) { m_max_clients = m; };
    void set_client_idletime (int t) { m_client_idletime = (t > 1) ? t : 600; };
    void set_target_idletime (int t) { m_target_idletime = (t > 1) ? t : 600; };
    int get_target_idletime () { return m_target_idletime; }
    int set_config(const char *name);
    void reconfig() { m_reconfig_flag = 1; }
    int send_to_client(Z_APDU *apdu);
    int server(const char *addr);
    void pre_init();
    int get_log_mask() { return m_log_mask; };
    int handle_init_response_for_invalid_session(Z_APDU *apdu);
    void set_debug_mode(int mode);
    void send_response_fail_client(const char *addr);
    int m_num_msg_threads;
    Msg_Thread *m_my_thread;
    void base64_decode(const char *base64, char *buf, int buf_len);
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

