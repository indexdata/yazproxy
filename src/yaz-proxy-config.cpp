/* This file is part of YAZ proxy
   Copyright (C) 1998-2019 Index Data

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

#include <ctype.h>
#include <stdlib.h>

#include <yaz/log.h>
#include "proxyp.h"
#include <yaz/oid_db.h>

class Yaz_ProxyConfigP {
    friend class Yaz_ProxyConfig;

    Yaz_ProxyModules m_modules;
    int mycmp(const char *hay, const char *item, size_t len);
    int match_list(int v, const char *m);
    int atoi_l(const char **cp);
#if YAZ_HAVE_XSLT
    void load_modules(void);
    int check_schema(xmlNodePtr ptr, Z_RecordComposition *comp,
                     const char *schema_identifier);
    xmlDocPtr m_docPtr;
    xmlNodePtr m_proxyPtr;
    void return_target_info(xmlNodePtr ptr, const char **url,
                            int *limit_bw, int *limit_pdu, int *limit_req,
                            int *limit_search,
                            int *target_idletime, int *client_idletime,
                            int *max_sockets,
                            int *keepalive_limit_bw, int *keepalive_limit_pdu,
                            int *pre_init, const char **cql2rpn,
                            const char **negotiation_charset,
                            const char **negotiation_lang,
                            const char **target_charset,
                            const char **default_client_query_charset);
    void return_limit(xmlNodePtr ptr,
                      int *limit_bw, int *limit_pdu, int *limit_req,
                      int *limit_search);
    int check_type_1(ODR odr, xmlNodePtr ptr, Z_RPNQuery *query,
                     char **addinfo);
    xmlNodePtr find_target_node(const char *name);
    const char *get_text(xmlNodePtr ptr);
    void get_period(xmlNodePtr ptr, int *period);
    int check_type_1_attributes(ODR odr, xmlNodePtr ptr,
                                Z_AttributeList *attrs,
                                char **addinfo);
    int check_type_1_structure(ODR odr, xmlNodePtr ptr, Z_RPNStructure *q,
                               char **addinfo);
    int get_explain_ptr(const char *db,
                        xmlNodePtr *ptr_target, xmlNodePtr *ptr_explain);
#endif
    Yaz_ProxyConfigP();
    ~Yaz_ProxyConfigP();
};

Yaz_ProxyConfigP::Yaz_ProxyConfigP()  : m_modules()
{
#if YAZ_HAVE_XSLT
    m_docPtr = 0;
    m_proxyPtr = 0;
#endif
}

Yaz_ProxyConfigP::~Yaz_ProxyConfigP()
{
#if YAZ_HAVE_XSLT
    if (m_docPtr)
        xmlFreeDoc(m_docPtr);
#endif
}

Yaz_ProxyConfig::Yaz_ProxyConfig()
{
    m_cp = new Yaz_ProxyConfigP();
}

Yaz_ProxyConfig::~Yaz_ProxyConfig()
{
    delete m_cp;
}

#if YAZ_HAVE_XSLT
void Yaz_ProxyConfigP::load_modules()
{
    if (!m_proxyPtr)
        return;
    xmlNodePtr ptr;
    for (ptr = m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        const char *fname;
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "module")
            && (fname = get_text(ptr)))
        {
            m_modules.add_module(fname);
        }
    }
}
#endif

int Yaz_ProxyConfig::read_xml(const char *fname)
{
#if YAZ_HAVE_XSLT
    xmlDocPtr ndoc = xmlParseFile(fname);

    if (!ndoc)
    {
        yaz_log(YLOG_WARN, "Config file %s not found or parse error", fname);
        return -1;  // no good
    }
    int noSubstitutions = xmlXIncludeProcess(ndoc);
    if (noSubstitutions == -1)
        yaz_log(YLOG_WARN, "XInclude processing failed on config %s", fname);

    xmlNodePtr proxyPtr = xmlDocGetRootElement(ndoc);
    if (!proxyPtr || proxyPtr->type != XML_ELEMENT_NODE ||
        strcmp((const char *) proxyPtr->name, "proxy"))
    {
        yaz_log(YLOG_WARN, "No proxy element in %s", fname);
        xmlFreeDoc(ndoc);
        return -1;
    }
    m_cp->m_proxyPtr = proxyPtr;

    // OK: release previous and make it the current one.
    if (m_cp->m_docPtr)
        xmlFreeDoc(m_cp->m_docPtr);
    m_cp->m_docPtr = ndoc;

    m_cp->m_modules.unload_modules();
    m_cp->load_modules();
    return 0;
#else
    return -2;
#endif
}

#if YAZ_HAVE_XSLT
const char *Yaz_ProxyConfigP::get_text(xmlNodePtr ptr)
{
    for(ptr = ptr->children; ptr; ptr = ptr->next)
        if (ptr->type == XML_TEXT_NODE)
        {
            xmlChar *t = ptr->content;
            if (t)
            {
                while (*t == ' ')
                    t++;
                return (const char *) t;
            }
        }
    return 0;
}

void Yaz_ProxyConfigP::get_period(xmlNodePtr ptr, int *period)
{
    struct _xmlAttr *attr;
    *period = 60;
    for (attr = ptr->properties; attr; attr = attr->next)
    {
        if (!strcmp((const char *) attr->name, "period") &&
            attr->children && attr->children->type == XML_TEXT_NODE)
            *period = atoi((const char *) attr->children->content);
    }
}
#endif

#if YAZ_HAVE_XSLT
void Yaz_ProxyConfigP::return_limit(xmlNodePtr ptr,
                                    int *limit_bw,
                                    int *limit_pdu,
                                    int *limit_req,
                                    int *limit_search)
{
    for (ptr = ptr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "bandwidth"))
        {
            const char *t = get_text(ptr);
            if (t)
                *limit_bw = atoi(t);
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "retrieve"))
        {
            const char *t = get_text(ptr);
            if (t)
                *limit_req = atoi(t);
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "pdu"))
        {
            const char *t = get_text(ptr);
            if (t)
                *limit_pdu = atoi(t);
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "search"))
        {
            const char *t = get_text(ptr);
            if (t)
                *limit_search = atoi(t);
        }
    }
}
#endif

#if YAZ_HAVE_XSLT
void Yaz_ProxyConfigP::return_target_info(xmlNodePtr ptr,
                                          const char **url,
                                          int *limit_bw,
                                          int *limit_pdu,
                                          int *limit_req,
                                          int *limit_search,
                                          int *target_idletime,
                                          int *client_idletime,
                                          int *max_sockets,
                                          int *keepalive_limit_bw,
                                          int *keepalive_limit_pdu,
                                          int *pre_init,
                                          const char **cql2rpn,
                                          const char **negotiation_charset,
                                          const char **negotiation_lang,
                                          const char **target_charset,
                                          const char **default_client_query_charset)
{
    *pre_init = 0;
    int no_url = 0;
    ptr = ptr->children;
    for (; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "preinit"))
        {
            const char *v = get_text(ptr);
            *pre_init = v ? atoi(v) : 1;
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "url"))
        {
            const char *t = get_text(ptr);
            if (t && no_url < MAX_ZURL_PLEX)
            {
                url[no_url++] = t;
                url[no_url] = 0;
            }
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "keepalive"))
        {
            int dummy;
            *keepalive_limit_bw = 500000;
            *keepalive_limit_pdu = 1000;
            return_limit(ptr, keepalive_limit_bw, keepalive_limit_pdu,
                         &dummy, &dummy);
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "limit"))
            return_limit(ptr, limit_bw, limit_pdu, limit_req,
                         limit_search);
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "target-timeout"))
        {
            const char *t = get_text(ptr);
            if (t)
            {
                *target_idletime = atoi(t);
                if (*target_idletime < 0)
                    *target_idletime = 0;
            }
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "client-timeout"))
        {
            const char *t = get_text(ptr);
            if (t)
            {
                *client_idletime = atoi(t);
                if (*client_idletime < 0)
                    *client_idletime = 0;
            }
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "max-sockets"))
        {
            const char *t = get_text(ptr);
            if (t && max_sockets)
            {
                *max_sockets = atoi(t);
            }
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "cql2rpn"))
        {
            const char *t = get_text(ptr);
            if (t)
                *cql2rpn = t;
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "target-charset"))
        {
            const char *t = get_text(ptr);
            if (t && target_charset)
                *target_charset = t;
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "default-client-charset"))
        {
            const char *t = get_text(ptr);
            if (t && default_client_query_charset)
                *default_client_query_charset = t;
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "negotiation-charset"))
        {
            const char *t = get_text(ptr);
            if (t)
                *negotiation_charset = t;
        }
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "negotiation-lang"))
        {
            const char *t = get_text(ptr);
            if (t)
                *negotiation_lang = t;
        }
    }
}
#endif

int Yaz_ProxyConfigP::atoi_l(const char **cp)
{
    int v = 0;
    while (**cp && isdigit(**cp))
    {
        v = v*10 + (**cp - '0');
        (*cp)++;
    }
    return v;
}

int Yaz_ProxyConfigP::match_list(int v, const char *m)
{
    while(m && *m)
    {
        while(*m && isspace(*m))
            m++;
        if (*m == '*')
            return 1;
        int l = atoi_l(&m);
        int h = l;
        if (*m == '-')
        {
            ++m;
            h = atoi_l(&m);
        }
        if (v >= l && v <= h)
          return 1;
        if (*m == ',')
            m++;
    }
    return 0;
}

#if YAZ_HAVE_XSLT
int Yaz_ProxyConfigP::check_type_1_attributes(ODR odr, xmlNodePtr ptrl,
                                              Z_AttributeList *attrs,
                                              char **addinfo)
{
    int i;
    for (i = 0; i<attrs->num_attributes; i++)
    {
        Z_AttributeElement *el = attrs->attributes[i];

        if (!el->attributeType)
            continue;
        int type = *el->attributeType;
        Odr_int *value = 0;

        if (el->which == Z_AttributeValue_numeric && el->value.numeric)
            value = el->value.numeric;

        xmlNodePtr ptr;
        for(ptr = ptrl->children; ptr; ptr = ptr->next)
        {
            if (ptr->type == XML_ELEMENT_NODE &&
                !strcmp((const char *) ptr->name, "attribute"))
            {
                const char *match_type = 0;
                const char *match_value = 0;
                const char *match_error = 0;
                struct _xmlAttr *attr;
                for (attr = ptr->properties; attr; attr = attr->next)
                {
                    if (!strcmp((const char *) attr->name, "type") &&
                        attr->children && attr->children->type == XML_TEXT_NODE)
                        match_type = (const char *) attr->children->content;
                    if (!strcmp((const char *) attr->name, "value") &&
                        attr->children && attr->children->type == XML_TEXT_NODE)
                        match_value = (const char *) attr->children->content;
                    if (!strcmp((const char *) attr->name, "error") &&
                        attr->children && attr->children->type == XML_TEXT_NODE)
                        match_error = (const char *) attr->children->content;
                }
                if (match_type && match_value)
                {
                    char addinfo_str[20];
                    if (!match_list(type, match_type))
                        continue;

                    *addinfo_str = '\0';
                    if (!strcmp(match_type, "*"))
                        sprintf (addinfo_str, "%d", type);
                    else if (value)
                    {
                        if (!match_list(*value, match_value))
                            continue;
                        sprintf (addinfo_str, ODR_INT_PRINTF, *value);
                    }
                    else
                        continue;

                    if (match_error)
                    {
                        if (*addinfo_str)
                            *addinfo = odr_strdup(odr, addinfo_str);
                        return atoi(match_error);
                    }
                    break;
                }
            }
        }
    }
    return 0;
}
#endif

#if YAZ_HAVE_XSLT
int Yaz_ProxyConfigP::check_type_1_structure(ODR odr, xmlNodePtr ptr,
                                             Z_RPNStructure *q,
                                             char **addinfo)
{
    if (q->which == Z_RPNStructure_complex)
    {
        int e = check_type_1_structure(odr, ptr, q->u.complex->s1, addinfo);
        if (e)
            return e;
        e = check_type_1_structure(odr, ptr, q->u.complex->s2, addinfo);
        return e;
    }
    else if (q->which == Z_RPNStructure_simple)
    {
        if (q->u.simple->which == Z_Operand_APT)
        {
            return check_type_1_attributes(
                odr, ptr, q->u.simple->u.attributesPlusTerm->attributes,
                addinfo);
        }
    }
    return 0;
}
#endif

#if YAZ_HAVE_XSLT
int Yaz_ProxyConfigP::check_type_1(ODR odr, xmlNodePtr ptr, Z_RPNQuery *query,
                                   char **addinfo)
{
    // possibly check for Bib-1
    return check_type_1_structure(odr, ptr, query->RPNStructure, addinfo);
}
#endif

int Yaz_ProxyConfig::check_query(ODR odr, const char *name, Z_Query *query,
                                 char **addinfo)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;

    ptr = m_cp->find_target_node(name);
    if (ptr)
    {
        if (query->which == Z_Query_type_1 || query->which == Z_Query_type_101)
            return m_cp->check_type_1(odr, ptr, query->u.type_1, addinfo);
    }
#endif
    return 0;
}

#if YAZ_HAVE_XSLT
int Yaz_ProxyConfigP::check_schema(xmlNodePtr ptr, Z_RecordComposition *comp,
                                   const char *schema_identifier)
{
    char *esn = 0;
    int default_match = 1;
    if (comp && comp->which == Z_RecordComp_simple &&
        comp->u.simple && comp->u.simple->which == Z_ElementSetNames_generic)
    {
        esn = comp->u.simple->u.generic;
    }
    // if no ESN/schema was given accept..
    if (!esn)
        return 1;
    // check if schema identifier match
    if (schema_identifier && !strcmp(esn, schema_identifier))
        return 1;
    // Check each name element
    for (; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "name"))
        {
            xmlNodePtr tptr = ptr->children;
            default_match = 0;
            for (; tptr; tptr = tptr->next)
                if (tptr->type == XML_TEXT_NODE && tptr->content)
                {
                    xmlChar *t = tptr->content;
                    while (*t && isspace(*t))
                        t++;
                    int i = 0;
                    while (esn[i] && esn[i] == t[i])
                        i++;
                    if (!esn[i] && (!t[i] || isspace(t[i])))
                        return 1;
                }
        }
    }
    return default_match;
}
#endif

const char *Yaz_ProxyConfig::check_mime_type(const char *path)
{
    struct {
        const char *mask;
        const char *type;
    } types[] = {
        {".xml", "text/xml"},
        {".xsl", "text/xml"},
        {".tkl", "text/xml"},
        {".xsd", "text/xml"},
        {".html", "text/html"},
        {".jpg", "image/jpeg"},
        {".png", "image/png"},
        {".gif", "image/gif"},
        {".css", "text/css"},
        {".pdf", "application/pdf"},
        {0, "text/plain"},
        {0, 0},
    };
    int i;
    size_t plen = strlen (path);
    for (i = 0; types[i].type; i++)
        if (types[i].mask == 0)
            return types[i].type;
        else
        {
            size_t mlen = strlen(types[i].mask);
            if (plen > mlen && !memcmp(path+plen-mlen, types[i].mask, mlen))
                return types[i].type;
        }
    return "application/octet-stream";
}


void Yaz_ProxyConfig::target_authentication(const char *name,
                                            ODR odr, Z_InitRequest *req)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr = m_cp->find_target_node(name);
    if (!ptr)
        return ;

    for (ptr = ptr->children; ptr; ptr = ptr->next)
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "target-authentication"))
        {
            struct _xmlAttr *attr;
            const char *type = "open";
            for (attr = ptr->properties; attr; attr = attr->next)
            {
                if (!strcmp((const char *) attr->name, "type") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    type = (const char *) attr->children->content;
            }
            const char *t = m_cp->get_text(ptr);
            if (!t || !strcmp(type, "none"))
            {
                req->idAuthentication = 0;
            }
            else if (!strcmp(type, "anonymous"))
            {
                req->idAuthentication =
                    (Z_IdAuthentication *)
                    odr_malloc (odr, sizeof(*req->idAuthentication));
                req->idAuthentication->which =
                    Z_IdAuthentication_anonymous;
                req->idAuthentication->u.anonymous = odr_nullval();
            }
            else if (!strcmp(type, "open"))
            {
                req->idAuthentication =
                    (Z_IdAuthentication *)
                    odr_malloc (odr, sizeof(*req->idAuthentication));
                req->idAuthentication->which =
                    Z_IdAuthentication_open;
                req->idAuthentication->u.open = odr_strdup (odr, t);
            }
            else if (!strcmp(type, "idPass"))
            {
                char user[64], group[64], password[64];
                *group = '\0';
                *password = '\0';
                *user = '\0';
                sscanf(t, "%63[^:]:%63[^:]:%63s", user, group, password);

                req->idAuthentication =
                    (Z_IdAuthentication *)
                    odr_malloc (odr, sizeof(*req->idAuthentication));
                req->idAuthentication->which =
                    Z_IdAuthentication_idPass;
                req->idAuthentication->u.idPass =
                    (Z_IdPass*) odr_malloc(odr, sizeof(Z_IdPass));
                req->idAuthentication->u.idPass->userId =
                    *user ? odr_strdup(odr, user) : 0;
                req->idAuthentication->u.idPass->groupId =
                    *group ? odr_strdup(odr, group) : 0;
                req->idAuthentication->u.idPass->password =
                    *password ? odr_strdup(odr, password) : 0;
            }
        }
#endif
}

int Yaz_ProxyConfig::client_authentication(const char *name,
                                           const char *user,
                                           const char *group,
                                           const char *password,
                                           const char *peer_IP)
{
    int ret = YAZPROXY_RET_NOT_ME;
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;
    ptr = m_cp->find_target_node(name);
    if (!ptr)
        return 1;
    for (ptr = ptr->children; ptr; ptr = ptr->next)
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "client-authentication"))
        {
            struct _xmlAttr *attr;
            const char *module_name = 0;
            for (attr = ptr->properties; attr; attr = attr->next)
            {
                if (!strcmp((const char *) attr->name, "module") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    module_name = (const char *) attr->children->content;
            }
            ret = m_cp->m_modules.authenticate(module_name,
                                               name, ptr,
                                               user, group, password,
                                               peer_IP
                );
            if (ret != YAZPROXY_RET_NOT_ME)
                break;
        }
#endif
    if (ret == YAZPROXY_RET_PERM)
        return 0;
    return 1;
}

int Yaz_ProxyConfig::global_client_authentication(const char *user,
                                                  const char *group,
                                                  const char *password,
                                                  const char *peer_IP)
{
    int ret = YAZPROXY_RET_NOT_ME;
#if YAZ_HAVE_XSLT
    if (!m_cp->m_proxyPtr)
        return 1;
    xmlNodePtr ptr;
    for (ptr = m_cp->m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "client-authentication"))
        {
            struct _xmlAttr *attr;
            const char *module_name = 0;
            for (attr = ptr->properties; attr; attr = attr->next)
            {
                if (!strcmp((const char *) attr->name, "module") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    module_name = (const char *) attr->children->content;
            }
            ret = m_cp->m_modules.authenticate(module_name,
                                               NULL, ptr,
                                               user, group, password,
                                               peer_IP
                );
            if (ret != YAZPROXY_RET_NOT_ME)
                break;
        }
    }
#endif
    if (ret == YAZPROXY_RET_PERM)
        return 0;
    return 1;
}

int Yaz_ProxyConfig::check_syntax(ODR odr, const char *name,
                                  Odr_oid *syntax, Z_RecordComposition *comp,
                                  char **addinfo,
                                  char **stylesheet, char **schema,
                                  char **backend_type,
                                  char **backend_charset,
                                  char **usemarcon_ini_stage1,
                                  char **usemarcon_ini_stage2,
                                  char **backend_elementset
                                  )
{
    if (stylesheet)
    {
        xfree (*stylesheet);
        *stylesheet = 0;
    }
    if (schema)
    {
        xfree (*schema);
        *schema = 0;
    }
    if (backend_type)
    {
        xfree (*backend_type);
        *backend_type = 0;
    }
    if (backend_charset)
    {
        xfree (*backend_charset);
        *backend_charset = 0;
    }
    if (usemarcon_ini_stage1)
    {
        xfree (*usemarcon_ini_stage1);
        *usemarcon_ini_stage1 = 0;
    }
    if (usemarcon_ini_stage2)
    {
        xfree (*usemarcon_ini_stage2);
        *usemarcon_ini_stage2 = 0;
    }
    xfree(*backend_elementset);
    *backend_elementset = 0;
#if YAZ_HAVE_XSLT
    int syntax_has_matched = 0;
    xmlNodePtr ptr;

    ptr = m_cp->find_target_node(name);
    if (!ptr)
        return 0;
    for(ptr = ptr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "syntax"))
        {
            int match = 0;  // if we match record syntax
            const char *match_type = 0;
            const char *match_error = 0;
            const char *match_marcxml = 0;
            const char *match_stylesheet = 0;
            const char *match_identifier = 0;
            const char *match_backend_type = 0;
            const char *match_backend_charset = 0;
            const char *match_usemarcon_ini_stage1 = 0;
            const char *match_usemarcon_ini_stage2 = 0;
            const char *match_elementset = 0;
            struct _xmlAttr *attr;
            for (attr = ptr->properties; attr; attr = attr->next)
            {
                if (!strcmp((const char *) attr->name, "type") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_type = (const char *) attr->children->content;
                else if (!strcmp((const char *) attr->name, "error") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_error = (const char *) attr->children->content;
                else if (!strcmp((const char *) attr->name, "marcxml") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_marcxml = (const char *) attr->children->content;
                else if (!strcmp((const char *) attr->name, "stylesheet") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_stylesheet = (const char *) attr->children->content;
                else if (!strcmp((const char *) attr->name, "identifier") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_identifier = (const char *) attr->children->content;
                else if (!strcmp((const char *) attr->name, "backendtype") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_backend_type = (const char *)
                        attr->children->content;
                else if (!strcmp((const char *) attr->name, "backendcharset") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_backend_charset = (const char *)
                        attr->children->content;
                else if (!strcmp((const char *) attr->name, "usemarconstage1") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_usemarcon_ini_stage1 = (const char *)
                        attr->children->content;
                else if (!strcmp((const char *) attr->name, "usemarconstage2") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_usemarcon_ini_stage2 = (const char *)
                        attr->children->content;
                else if (!strcmp((const char *) attr->name, "backendelementset") &&
                    attr->children && attr->children->type == XML_TEXT_NODE)
                    match_elementset = (const char *) attr->children->content;
                else
                {
                    yaz_log(YLOG_WARN, "0 Unknown attribute %s in <syntax>",
                            (const char *) attr->name);
                }
            }
            if (match_type)
            {
                if (!strcmp(match_type, "*"))
                    match = 1;
                else if (!strcmp(match_type, "none"))
                {
                    if (syntax == 0)
                        match = 1;
                }
                else if (syntax)
                {
                    Odr_oid *match_oid
                        = yaz_string_to_oid_odr(yaz_oid_std(),
                                                CLASS_RECSYN, match_type,
                                                odr);
                    if (oid_oidcmp(match_oid, syntax) == 0)
                        match = 1;
                }
            }
            if (match)
            {
                if (!match_error)
                    syntax_has_matched = 1;
                match = m_cp->check_schema(ptr->children, comp,
                                           match_identifier);
            }
            if (match)
            {
                if (stylesheet && match_stylesheet)
                {
                    xfree(*stylesheet);
                    *stylesheet = xstrdup(match_stylesheet);
                }
                if (schema && match_identifier)
                {
                    xfree(*schema);
                    *schema = xstrdup(match_identifier);
                }
                if (backend_type && match_backend_type)
                {
                    xfree(*backend_type);
                    *backend_type = xstrdup(match_backend_type);
                }
                if (backend_charset && match_backend_charset)
                {
                    xfree(*backend_charset);
                    *backend_charset = xstrdup(match_backend_charset);
                }
                if (match_elementset)
                {
                    xfree(*backend_elementset);
                    *backend_elementset = xstrdup(match_elementset);
                }
                if (usemarcon_ini_stage1 && match_usemarcon_ini_stage1)
                {
                    xfree(*usemarcon_ini_stage1);
                    *usemarcon_ini_stage1 = xstrdup(match_usemarcon_ini_stage1);
                }
                if (usemarcon_ini_stage1 && match_usemarcon_ini_stage2)
                {
                    xfree(*usemarcon_ini_stage2);
                    *usemarcon_ini_stage2 = xstrdup(match_usemarcon_ini_stage2);
                }
                if (match_marcxml)
                {
                    return -1;
                }
                if (match_error)
                {
                    if (syntax_has_matched)  // if syntax OK, bad schema/ESN
                        return 25;
                    if (syntax)
                    {
                        char dotoid_str[OID_STR_MAX];
                        oid_oid_to_dotstring(syntax, dotoid_str);
                        *addinfo = odr_strdup(odr, dotoid_str);
                    }
                    return atoi(match_error);
                }
                return 0;
            }
        }
    }
#endif
    return 0;
}


#if YAZ_HAVE_XSLT

xmlNodePtr Yaz_ProxyConfigP::find_target_node(const char *name)
{
    /* db seems always to be passed as NULL */
    xmlNodePtr ptr;
    if (!m_proxyPtr)
        return 0;
    for (ptr = m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "target"))
        {
            // default one ?
            if (!name)
            {
                // <target default="1"> ?
                struct _xmlAttr *attr;
                for (attr = ptr->properties; attr; attr = attr->next)
                    if (!strcmp((const char *) attr->name, "default") &&
                        attr->children && attr->children->type == XML_TEXT_NODE)
                    {
                        xmlChar *t = attr->children->content;
                        if (!t || *t == '1')
                            return ptr;
                    }
            }
            else
            {
                // <target name="name"> ?
                struct _xmlAttr *attr;
                for (attr = ptr->properties; attr; attr = attr->next)
                    if (!strcmp((const char *) attr->name, "name"))
                    {
                        if (attr->children
                            && attr->children->type==XML_TEXT_NODE
                            && attr->children->content
                            && (!strcmp((const char *) attr->children->content,
                                        name)
                                || !strcmp((const char *) attr->children->content,
                                           "*")))
                        {
                            return ptr;
                        }
                    }
            }
        }
    }
    return 0;
}
#endif

int Yaz_ProxyConfig::get_target_no(int no,
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
                                   const char **target_charset,
                                   const char **default_client_query_charset)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;
    if (!m_cp->m_proxyPtr)
        return 0;
    int i = 0;
    for (ptr = m_cp->m_proxyPtr->children; ptr; ptr = ptr->next)
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "target"))
        {
            if (i == no)
            {
                struct _xmlAttr *attr;
                for (attr = ptr->properties; attr; attr = attr->next)
                    if (!strcmp((const char *) attr->name, "name"))
                    {
                        if (attr->children
                            && attr->children->type==XML_TEXT_NODE
                            && attr->children->content)
                            *name = (const char *) attr->children->content;
                    }
                m_cp->return_target_info(
                    ptr, url,
                    limit_bw, limit_pdu, limit_req,
                    limit_search,
                    target_idletime, client_idletime,
                    max_sockets,
                    keepalive_limit_bw, keepalive_limit_pdu,
                    pre_init, cql2rpn,
                    negotiation_charset, negotiation_lang, target_charset,
                    default_client_query_charset);
                return 1;
            }
            i++;
        }
#endif
    return 0;
}

int Yaz_ProxyConfigP::mycmp(const char *hay, const char *item, size_t len)
{
    if (len == strlen(item) && memcmp(hay, item, len) == 0)
        return 1;
    return 0;
}

int Yaz_ProxyConfig::get_file_access_info(const char *path)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;
    if (!m_cp->m_proxyPtr)
        return 0;
    for (ptr = m_cp->m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "docpath"))
        {
            const char *docpath = m_cp->get_text(ptr);
            size_t docpath_len = strlen(docpath);
            if (docpath_len < strlen(path) && path[docpath_len] == '/'
                && !memcmp(docpath, path, docpath_len))
                return 1;
        }
    }
#endif
    return 0;
}

void Yaz_ProxyConfig::get_generic_info(int *log_mask,
                                       int *max_clients,
                                       int *max_connect,
                                       int *limit_connect,
                                       int *period_connect,
                                       int *num_msg_threads)
{
    *max_connect = 0;
    *limit_connect = 0;
    *num_msg_threads = 0;
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;
    if (!m_cp->m_proxyPtr)
        return;
    for (ptr = m_cp->m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE
            && !strcmp((const char *) ptr->name, "log"))
        {
            const char *v = m_cp->get_text(ptr);
            *log_mask = 0;
            while (v && *v)
            {
                const char *cp = v;
                while (*cp && *cp != ',' && !isspace(*cp))
                    cp++;
                size_t len = cp - v;
                if (m_cp->mycmp(v, "client-apdu", len))
                    *log_mask |= PROXY_LOG_APDU_CLIENT;
                if (m_cp->mycmp(v, "server-apdu", len))
                    *log_mask |= PROXY_LOG_APDU_SERVER;
                if (m_cp->mycmp(v, "client-requests", len))
                    *log_mask |= PROXY_LOG_REQ_CLIENT;
                if (m_cp->mycmp(v, "server-requests", len))
                    *log_mask |= PROXY_LOG_REQ_SERVER;
                if (m_cp->mycmp(v, "client-ip", len))
                    *log_mask |= PROXY_LOG_IP_CLIENT;
                if (isdigit(*v))
                    *log_mask |= atoi(v);
                if (*cp == ',')
                    cp++;
                while (*cp && isspace(*cp))
                    cp++;
                v = cp;
            }
        }
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "max-clients"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
            {
                *max_clients = atoi(t);
                if (*max_clients  < 1)
                    *max_clients = 1;
            }
        }
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "period-connect"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
                *period_connect = atoi(t);
        }
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "max-connect"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
            {
                *max_connect = atoi(t);
            }
        }
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "limit-connect"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
            {
                *limit_connect = atoi(t);
            }
        }
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "target"))
            ;
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "docpath"))
            ;
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "module"))
            ;
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "client-authentication"))
            ;
        else if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "threads"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
            {
                *num_msg_threads = atoi(t);
            }
        }
        else if (ptr->type == XML_ELEMENT_NODE)
        {
            yaz_log(YLOG_WARN, "0 Unknown element %s in yazproxy config",
                    ptr->name);
        }
    }
#endif
}

#if YAZ_HAVE_XSLT
int Yaz_ProxyConfigP::get_explain_ptr(const char *db,
                                      xmlNodePtr *ptr_target,
                                      xmlNodePtr *ptr_explain)
{
    xmlNodePtr ptr;
    if (!m_proxyPtr)
        return 0;
    if (!db)
        return 0;
    for (ptr = m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "target"))
        {
            int db_match_on_name = 0;
            struct _xmlAttr *attr;

            for (attr = ptr->properties; attr; attr = attr->next)
                if (!strcmp((const char *) attr->name, "name"))
                {
                    if (attr->children
                        && attr->children->type==XML_TEXT_NODE
                        && attr->children->content
                        && (!strcmp((const char *) attr->children->content,
                                    db)))
                        db_match_on_name = 1;
                }
            *ptr_target = ptr;
            xmlNodePtr ptr = (*ptr_target)->children;
            for (; ptr; ptr = ptr->next)
            {
                if (ptr->type == XML_ELEMENT_NODE &&
                    !strcmp((const char *) ptr->name, "explain"))
                {
                    *ptr_explain = ptr;
                    xmlNodePtr ptr = (*ptr_explain)->children;

                    for (; ptr; ptr = ptr->next)
                        if (ptr->type == XML_ELEMENT_NODE &&
                            !strcmp((const char *) ptr->name, "serverInfo"))
                            break;
                    if (!ptr)
                        continue;
                    for (ptr = ptr->children; ptr; ptr = ptr->next)
                        if (ptr->type == XML_ELEMENT_NODE &&
                            !strcmp((const char *) ptr->name, "database"))
                            break;

                    if (!ptr)
                        continue;
                    for (ptr = ptr->children; ptr; ptr = ptr->next)
                        if (ptr->type == XML_TEXT_NODE &&
                            ptr->content &&
                            !strcmp((const char *) ptr->content, db))
                            break;
                    if (!ptr)
                        continue;
                    return 1;
                }
            }
            if (db_match_on_name)
                return 1;
        }
    }
    return 0;
}
#endif

const char *Yaz_ProxyConfig::get_explain_name(const char *db,
                                              const char **backend_db)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr_target, ptr_explain;
    if (m_cp->get_explain_ptr(db, &ptr_target, &ptr_explain)
        && ptr_target)
    {
        struct _xmlAttr *attr;
        const char *name = 0;

        for (attr = ptr_target->properties; attr; attr = attr->next)
            if (!strcmp((const char *) attr->name, "name")
                && attr->children
                && attr->children->type==XML_TEXT_NODE
                && attr->children->content
                && attr->children->content[0])
            {
                name = (const char *)attr->children->content;
                break;
            }
        if (name)
        {
            for (attr = ptr_target->properties; attr; attr = attr->next)
                if (!strcmp((const char *) attr->name, "database"))
                {
                    if (attr->children
                        && attr->children->type==XML_TEXT_NODE
                        && attr->children->content)
                        *backend_db = (const char *) attr->children->content;
                }
            return name;
        }
    }
#endif
    return 0;
}

char *Yaz_ProxyConfig::get_explain_doc(ODR odr, const char *name,
                                       const char *db, int *len,
                                       int *http_status)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr_target, ptr_explain;
    if (m_cp->get_explain_ptr(db, &ptr_target, &ptr_explain))
    {
        if (!ptr_explain)
        {
            *http_status = 500;
            return 0;
        }
        else
        {
            xmlNodePtr ptr2 = xmlCopyNode(ptr_explain, 1);

            xmlDocPtr doc = xmlNewDoc((const xmlChar *) "1.0");

            xmlDocSetRootElement(doc, ptr2);

            xmlChar *buf_out;
            xmlDocDumpMemory(doc, &buf_out, len);
            char *content = (char*) odr_malloc(odr, *len);
            memcpy(content, buf_out, *len);

            xmlFree(buf_out);
            xmlFreeDoc(doc);
            return content;
        }
    }
#endif
    *http_status = 404;
    return 0;
}

void Yaz_ProxyConfig::get_target_info(const char *name,
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
                                      const char **negotiation_charset,
                                      const char **negotiation_lang,
                                      const char **target_charset,
                                      const char **default_client_query_charset)
{
#if YAZ_HAVE_XSLT
    xmlNodePtr ptr;
    if (!m_cp->m_proxyPtr)
    {
        url[0] = name;
        url[1] = 0;
        return;
    }
    url[0] = 0;
    for (ptr = m_cp->m_proxyPtr->children; ptr; ptr = ptr->next)
    {
        if (ptr->type == XML_ELEMENT_NODE &&
            !strcmp((const char *) ptr->name, "max-clients"))
        {
            const char *t = m_cp->get_text(ptr);
            if (t)
            {
                *max_clients = atoi(t);
                if (*max_clients  < 1)
                    *max_clients = 1;
            }
        }
    }
    ptr = m_cp->find_target_node(name);
    if (ptr)
    {
        if (name)
        {
            url[0] = name;
            url[1] = 0;
        }
        m_cp->return_target_info(ptr, url, limit_bw, limit_pdu, limit_req,
                                 limit_search,
                                 target_idletime, client_idletime,
                                 max_sockets,
                                 keepalive_limit_bw, keepalive_limit_pdu,
                                 pre_init, cql2rpn,
                                 negotiation_charset, negotiation_lang,
                                 target_charset,
                                 default_client_query_charset);
    }
#else
    *url = name;
    return;
#endif
}


/*
 * Local variables:
 * c-basic-offset: 4
 * c-file-style: "Stroustrup"
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

