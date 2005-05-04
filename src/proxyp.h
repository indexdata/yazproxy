/* $Id: proxyp.h,v 1.4 2005-05-04 08:31:44 adam Exp $
   Copyright (c) 1998-2005, Index Data.

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
    CDetails *m_stage1;
    CDetails *m_stage2;
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
    void convert_type_1(Z_RPNQuery *q, ODR o);
private:
    void convert_type_1(char *buf_in, int len_in,
			char **buf_out, int *len_out,
			ODR o);
    void convert_type_1(Z_Term *q, ODR o);
    void convert_type_1(Z_RPNStructure *q, ODR o);
    void convert_type_1(Z_Operand *q, ODR o);
    char *m_target_query_charset;
    char *m_client_query_charset;
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
		      int *target_idletime,
		      int *client_idletime,
		      int *max_clients,
		      int *keepalive_limit_bw,
		      int *keepalive_limit_pdu,
		      int *pre_init,
		      const char **cql2rpn,
		      const char **authentication,
		      const char **negotiation_charset,
		      const char **negotiation_lang,
		      const char **query_charset);
    
    void get_generic_info(int *log_mask, int *max_clients);

    void get_target_info(const char *name, const char **url,
			 int *limit_bw, int *limit_pdu, int *limit_req,
			 int *target_idletime, int *client_idletime,
			 int *max_clients,
			 int *keepalive_limit_bw, int *keepalive_limit_pdu,
			 int *pre_init,
			 const char **cql2rpn,
			 const char **negotiation_charset,
			 const char **negotiation_lang,
			 const char **query_charset);

    const char *check_mime_type(const char *path);
    int check_query(ODR odr, const char *name, Z_Query *query, char **addinfo);
    int check_syntax(ODR odr, const char *name,
		     Odr_oid *syntax, Z_RecordComposition *comp,
		     char **addinfo, char **stylesheet, char **schema,
		     char **backend_type, char **backend_charset,
		     char **usemarcon_ini_stage1, char **usemarcon_ini_stage2);

    void target_authentication(const char *name,
			       ODR odr,
			       Z_InitRequest *req);

    int client_authentication(const char *name,
			      const char *user, const char *group,
			      const char *password);
    char *get_explain_doc(ODR odr, const char *name, const char *db,
			  int *len);
    const char *get_explain_name(const char *db, const char **backend_db);
 private:
    void operator=(const Yaz_ProxyConfig &conf);
    class Yaz_ProxyConfigP *m_cp;
};

class Yaz_RecordCache {
 public:
    Yaz_RecordCache ();
    ~Yaz_RecordCache ();
    void add (ODR o, Z_NamePlusRecordList *npr, int start, int hits);
    
    int lookup (ODR o, Z_NamePlusRecordList **npr, int start, int num,
		Odr_oid *syntax, Z_RecordComposition *comp);
    void clear();

    void copy_searchRequest(Z_SearchRequest *sr);
    void copy_presentRequest(Z_PresentRequest *pr);
    void set_max_size(int sz);
 private:
    NMEM m_mem;
    Yaz_RecordCache_Entry *m_entries;
    Z_SearchRequest *m_searchRequest;
    Z_PresentRequest *m_presentRequest;
    int match (Yaz_RecordCache_Entry *entry,
	       Odr_oid *syntax, int offset,
	       Z_RecordComposition *comp);
    int m_max_size;
};

class Yaz_ProxyClient : public Yaz_Z_Assoc {
    friend class Yaz_Proxy;
    Yaz_ProxyClient(IYaz_PDU_Observable *the_PDU_Observable,
		    Yaz_Proxy *parent);
    ~Yaz_ProxyClient();
    void recv_GDU(Z_GDU *apdu, int len);
    void recv_Z_PDU(Z_APDU *apdu, int len);
    void recv_HTTP_response(Z_HTTP_Response *apdu, int len);
    IYaz_PDU_Observer* sessionNotify
	(IYaz_PDU_Observable *the_PDU_Observable, int fd);
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
    Yaz_Z_Query *m_last_query;
    Yaz_Z_Databases m_last_databases;
    char *m_last_resultSetId;
    int m_last_ok;
    int m_last_resultCount;
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
    Yaz_RecordCache m_cache;
    void pre_init_client();
    int m_target_idletime;
    Yaz_Proxy *m_root;
};

