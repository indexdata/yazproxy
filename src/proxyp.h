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

#if YAZ_HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

#if HAVE_USEMARCON
#include <usemarconlib.h>
#include <defines.h>
#endif

#include <yazpp/record-cache.h>
#include <yazproxy/proxy.h>
#include <yazproxy/module.h>

struct Yaz_RecordCache_Entry;

class Yaz_usemarcon {
 public:
    Yaz_usemarcon();
    ~Yaz_usemarcon();

    int convert(const char *stage1, const char *stage2,
                const char *input, int input_len,
                char **output, int *output_len);
#if HAVE_USEMARCON
    Usemarcon *m_stage1;
    Usemarcon *m_stage2;
#else
    int dummy;
#endif
};

class Yaz_CharsetConverter {
public:
    Yaz_CharsetConverter();
    ~Yaz_CharsetConverter();
    void set_target_query_charset(const char *s);
    void set_client_query_charset(const char *org);
    const char *get_client_query_charset(void);
    const char *get_target_query_charset(void);
    void convert_type_1(Z_RPNQuery *q, ODR o);
    void convert_term(Z_Term *q, ODR o);
    void set_client_charset_selected(int sel);
    int get_client_charset_selected();
private:
    void convert_type_1(char *buf_in, int len_in,
                        char **buf_out, int *len_out,
                        ODR o);
    void convert_type_1(Z_Term *q, ODR o);
    void convert_type_1(Z_RPNStructure *q, ODR o);
    void convert_type_1(Z_Operand *q, ODR o);
    char *m_target_query_charset;
    char *m_client_query_charset;
    int m_client_charset_selected;
    yaz_iconv_t m_ct;
    WRBUF m_wrbuf;
};

class Yaz_ProxyConfig {
public:
    Yaz_ProxyConfig();
    ~Yaz_ProxyConfig();
    int read_xml(const char *fname);

    int get_target_no(int no,
                      const char **name,
                      const char **url,
                      int *limit_bw,
                      int *limit_pdu,
                      int *limit_req,
                      int *limit_search,
                      int *target_idletime,
                      int *client_idletime,
                      int *max_sockets,
                      int *max_clients,
                      int *keepalive_limit_bw,
                      int *keepalive_limit_pdu,
                      int *pre_init,
                      const char **cql2rpn,
                      const char **authentication,
                      const char **negotiation_charset,
                      const char **negotiation_lang,
                      const char **query_charset,
                      const char **default_client_query_charset);

    void get_generic_info(int *log_mask, int *max_clients,
                          int *max_connect, int *limit_connect,
                          int *period_connect,
                          int *msg_threads);

    int get_file_access_info(const char *path);

    void get_target_info(const char *name, const char **url,
                         int *limit_bw, int *limit_pdu, int *limit_req,
                         int *limit_search,
                         int *target_idletime, int *client_idletime,
                         int *max_sockets,
                         int *max_clients,
                         int *keepalive_limit_bw, int *keepalive_limit_pdu,
                         int *pre_init,
                         const char **cql2rpn,
                         const char **negotiation_charset,
                         const char **negotiation_lang,
                         const char **query_charset,
                         const char **default_client_query_charset);

    const char *check_mime_type(const char *path);
    int check_query(ODR odr, const char *name, Z_Query *query, char **addinfo);
    int check_syntax(ODR odr, const char *name,
                     Odr_oid *syntax, Z_RecordComposition *comp,
                     char **addinfo, char **stylesheet, char **schema,
                     char **backend_type, char **backend_charset,
                     char **usemarcon_ini_stage1, char **usemarcon_ini_stage2,
                     char **backend_elementset);

    void target_authentication(const char *name,
                               ODR odr,
                               Z_InitRequest *req);

    int client_authentication(const char *name,
                              const char *user, const char *group,
                              const char *password,
                              const char *peer_IP);
    int global_client_authentication(const char *user, const char *group,
                                     const char *password,
                                     const char *peer_IP);
    char *get_explain_doc(ODR odr, const char *name, const char *db,
                          int *len, int *http_status);
    const char *get_explain_name(const char *db, const char **backend_db);
    int check_is_defined_database(const char *name, const char *db);
 private:
    void operator=(const Yaz_ProxyConfig &conf);
    class Yaz_ProxyConfigP *m_cp;
};

class Yaz_ProxyClient : public yazpp_1::Z_Assoc {
    friend class Yaz_Proxy;
    Yaz_ProxyClient(yazpp_1::IPDU_Observable *the_PDU_Observable,
                    Yaz_Proxy *parent);
    ~Yaz_ProxyClient();
    void recv_GDU(Z_GDU *apdu, int len);
    void recv_Z_PDU(Z_APDU *apdu, int len);
    void recv_HTTP_response(Z_HTTP_Response *apdu, int len);
    IPDU_Observer* sessionNotify
        (yazpp_1::IPDU_Observable *the_PDU_Observable, int fd);
    void shutdown();
    Yaz_Proxy *m_server;
    void failNotify();
    void timeoutNotify();
    void connectNotify();
    int send_to_target(Z_APDU *apdu);
    const char *get_session_str();
    char *m_cookie;
    Yaz_ProxyClient *m_next;
    Yaz_ProxyClient **m_prev;
    int m_init_flag;
    yazpp_1::Yaz_Z_Query *m_last_query;
    yazpp_1::Yaz_Z_Databases m_last_databases;
    char *m_last_resultSetId;
    int m_last_ok;
    Odr_int m_last_resultCount;
    int m_sr_transform;
    int m_seqno;
    int m_waiting;
    int m_resultSetStartPoint;
    int m_bytes_sent;
    int m_bytes_recv;
    int m_pdu_recv;
    ODR m_init_odr;
    Z_APDU *m_initResponse;
    Z_Options *m_initResponse_options;
    Z_ProtocolVersion *m_initResponse_version;
    int m_initResponse_preferredMessageSize;
    int m_initResponse_maximumRecordSize;
    yazpp_1::RecordCache m_cache;
    void pre_init_client();
    int m_target_idletime;
    Yaz_Proxy *m_root;
    char *m_idAuthentication_ber_buf;
    int m_idAuthentication_ber_size;
    ODR m_idAuthentication_odr;
    void set_idAuthentication(Z_APDU *apdu);
    bool compare_idAuthentication(Z_APDU *apdu);
    bool compare_charset(Z_APDU *apdu);
};

/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

