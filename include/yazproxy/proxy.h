/* $Id: proxy.h,v 1.1 2004-04-11 11:37:01 adam Exp $
   Copyright (c) 1998-2004, Index Data.

This file is part of the yaz-proxy.

Zebra is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 2, or (at your option) any later
version.

Zebra is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with Zebra; see the file LICENSE.proxy.  If not, write to the
Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.
 */

#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif
#include <yaz++/z-assoc.h>
#include <yaz++/z-query.h>
#include <yaz++/z-databases.h>
#include <yaz++/cql2rpn.h>
#include <yaz/cql.h>
#include <yaz++/proxy/bw.h>
#if HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

class Yaz_Proxy;

#define MAX_ZURL_PLEX 10

#define PROXY_LOG_APDU_CLIENT 1
#define PROXY_LOG_APDU_SERVER 2
#define PROXY_LOG_REQ_CLIENT 4
#define PROXY_LOG_REQ_SERVER 8

struct Yaz_RecordCache_Entry;

class YAZ_EXPORT Yaz_ProxyConfig {
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
		      const char **cql2rpn);
    
    void get_generic_info(int *log_mask, int *max_clients);

    void get_target_info(const char *name, const char **url,
			 int *limit_bw, int *limit_pdu, int *limit_req,
			 int *target_idletime, int *client_idletime,
			 int *max_clients,
			 int *keepalive_limit_bw, int *keepalive_limit_pdu,
			 int *pre_init,
			 const char **cql2rpn);

    int check_query(ODR odr, const char *name, Z_Query *query, char **addinfo);
    int check_syntax(ODR odr, const char *name,
		     Odr_oid *syntax, Z_RecordComposition *comp,
		     char **addinfo, char **stylesheet, char **schema);
    char *get_explain(ODR odr, const char *name, const char *db,
		      int *len);
private:
    void operator=(const Yaz_ProxyConfig &conf);
    int mycmp(const char *hay, const char *item, size_t len);
#if HAVE_XSLT
    int check_schema(xmlNodePtr ptr, Z_RecordComposition *comp,
		     const char *schema_identifier);
    xmlDocPtr m_docPtr;
    xmlNodePtr m_proxyPtr;
    void return_target_info(xmlNodePtr ptr, const char **url,
			    int *limit_bw, int *limit_pdu, int *limit_req,
			    int *target_idletime, int *client_idletime,
			    int *keepalive_limit_bw, int *keepalive_limit_pdu,
			    int *pre_init, const char **cql2rpn);
    void return_limit(xmlNodePtr ptr,
		      int *limit_bw, int *limit_pdu, int *limit_req);
    int check_type_1(ODR odr, xmlNodePtr ptr, Z_RPNQuery *query,
		     char **addinfo);
    xmlNodePtr find_target_node(const char *name, const char *db);
    xmlNodePtr find_target_db(xmlNodePtr ptr, const char *db);
    const char *get_text(xmlNodePtr ptr);
    int check_type_1_attributes(ODR odr, xmlNodePtr ptr,
				Z_AttributeList *attrs,
				char **addinfo);
    int check_type_1_structure(ODR odr, xmlNodePtr ptr, Z_RPNStructure *q,
			       char **addinfo);
#endif
    int m_copy;
    int match_list(int v, const char *m);
    int atoi_l(const char **cp);
};

class YAZ_EXPORT Yaz_RecordCache {
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

/// Private class
class YAZ_EXPORT Yaz_ProxyClient : public Yaz_Z_Assoc {
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


/// Information Retrieval Proxy Server.
class YAZ_EXPORT Yaz_Proxy : public Yaz_Z_Assoc {
 private:
    char *get_cookie(Z_OtherInformation **otherInfo);
    char *get_proxy(Z_OtherInformation **otherInfo);
    Yaz_ProxyClient *get_client(Z_APDU *apdu, const char *cookie,
				const char *proxy_host);
    Z_APDU *result_set_optimize(Z_APDU *apdu);
    void shutdown();
    
    Yaz_ProxyClient *m_client;
    IYaz_PDU_Observable *m_PDU_Observable;
    Yaz_ProxyClient *m_clientPool;
    Yaz_Proxy *m_parent;
    int m_seqno;
    int m_max_clients;
    int m_log_mask;
    int m_keepalive_limit_bw;
    int m_keepalive_limit_pdu;
    int m_client_idletime;
    int m_target_idletime;
    char *m_proxyTarget;
    char *m_default_target;
    char *m_proxy_authentication;
    long m_seed;
    char *m_optimize;
    int m_session_no;         // sequence for each client session
    char m_session_str[30];  // session string (time:session_no)
    Yaz_ProxyConfig *m_config;
    char *m_config_fname;
    int m_bytes_sent;
    int m_bytes_recv;
    int m_bw_max;
    Yaz_bw m_bw_stat;
    int m_pdu_max;
    Yaz_bw m_pdu_stat;
    Z_GDU *m_bw_hold_PDU;
    int m_max_record_retrieve;
    void handle_max_record_retrieve(Z_APDU *apdu);
    void display_diagrecs(Z_DiagRec **pp, int num);
    Z_Records *create_nonSurrogateDiagnostics(ODR o, int error,
					      const char *addinfo);

    Z_APDU *handle_query_validation(Z_APDU *apdu);
    Z_APDU *handle_query_transformation(Z_APDU *apdu);

    Z_APDU *handle_syntax_validation(Z_APDU *apdu);
    const char *load_balance(const char **url);
    int m_reconfig_flag;
    Yaz_ProxyConfig *check_reconfigure();
    int m_request_no;
    int m_invalid_session;
    int m_marcxml_flag;
#if HAVE_XSLT
    xsltStylesheetPtr m_stylesheet_xsp;
#else
    void *m_stylesheet_xsp;
#endif
    int m_stylesheet_offset;
    Z_APDU *m_stylesheet_apdu;
    Z_NamePlusRecordList *m_stylesheet_nprl;
    char *m_schema;
    void convert_to_marcxml(Z_NamePlusRecordList *p);
    int convert_xsl(Z_NamePlusRecordList *p, Z_APDU *apdu);
    void convert_xsl_delay();
    Z_APDU *m_initRequest_apdu;
    int m_initRequest_preferredMessageSize;
    int m_initRequest_maximumRecordSize;
    Z_Options *m_initRequest_options;
    Z_ProtocolVersion *m_initRequest_version;
    NMEM m_initRequest_mem;
    Z_APDU *m_apdu_invalid_session;
    NMEM m_mem_invalid_session;
    int send_PDU_convert(Z_APDU *apdu);
    ODR m_s2z_odr_init;
    ODR m_s2z_odr_search;
    int m_s2z_hit_count;
    int m_s2z_packing;
    char *m_s2z_database;
    Z_APDU *m_s2z_init_apdu;
    Z_APDU *m_s2z_search_apdu;
    Z_APDU *m_s2z_present_apdu;
    char *m_s2z_stylesheet;
    char *m_soap_ns;
    int send_to_srw_client_error(int error, const char *add);
    int send_to_srw_client_ok(int hits, Z_Records *records, int start);
    int send_http_response(int code);
    int send_srw_response(Z_SRW_PDU *srw_pdu);
    int send_srw_explain_response(Z_SRW_diagnostic *diagnostics,
				  int num_diagnostics);
    int z_to_srw_diag(ODR o, Z_SRW_searchRetrieveResponse *srw_res,
		      Z_DefaultDiagFormat *ddf);
    int m_http_keepalive;
    const char *m_http_version;
    Yaz_cql2rpn m_cql2rpn;
#if HAVE_GETTIMEOFDAY
    struct timeval m_time_tv;
#endif
    void logtime();
    Z_ElementSetNames *mk_esn_from_schema(ODR o, const char *schema);
    Z_ReferenceId *m_referenceId;
    NMEM m_referenceId_mem;
#define NO_SPARE_SOLARIS_FD 10
    int m_lo_fd[NO_SPARE_SOLARIS_FD];
    void low_socket_open();
    void low_socket_close();
 public:
    Yaz_Proxy(IYaz_PDU_Observable *the_PDU_Observable,
	      Yaz_Proxy *parent = 0);
    ~Yaz_Proxy();
    void inc_request_no();
    void recv_GDU(Z_GDU *apdu, int len);
    void handle_incoming_HTTP(Z_HTTP_Request *req);
    void handle_incoming_Z_PDU(Z_APDU *apdu);
    IYaz_PDU_Observer* sessionNotify
	(IYaz_PDU_Observable *the_PDU_Observable, int fd);
    void failNotify();
    void timeoutNotify();
    void connectNotify();
    void markInvalid();
    const char *option(const char *name, const char *value);
    void set_default_target(const char *target);
    void set_proxy_authentication (const char *auth);
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
};

