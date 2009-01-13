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

#include <signal.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <stdarg.h>
#include <stdlib.h>

#include <yaz/log.h>
#include <yaz/options.h>
#include <yaz/daemon.h>

#include <yazpp/socket-manager.h>
#include <yazpp/pdu-assoc.h>
#include <yazproxy/proxy.h>

#if YAZ_HAVE_XSLT
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#endif

#if YAZ_HAVE_EXSLT
#include <libexslt/exslt.h>
#endif

using namespace yazpp_1;

void usage(char *prog)
{
    fprintf (stderr, "%s: [-a log] [-c config] [-D]\n"
             " [-i sec] [-l log] [-m num] [-n num] [-p pidfile]"
             " [-t target] [-T sec] [-u uid]\n"
             " [-v level] [-X] [-V] @:port\n", prog);
    exit (1);
}

static char *pid_fname = 0;
static char *uid = 0;
static char *log_file = 0;
static unsigned int daemon_flags = YAZ_DAEMON_KEEPALIVE;
static int no_limit_files = 0;

int args(Yaz_Proxy *proxy, int argc, char **argv)
{
    char *addr = 0;
    char *arg;
    char *prog = argv[0];
    int ret;

    while ((ret = options("o:a:Dt:v:c:u:i:m:l:T:p:n:VX",
                          argv, argc, &arg)) != -2)
    {
        int err;
        switch (ret)
        {
        case 0:
            if (addr)
            {
                usage(prog);
                return 1;
            }
            addr = arg;
            break;
        case 'a':
            proxy->set_APDU_log(arg);
            break;
        case 'c':
            err = proxy->set_config(arg);
            if (err == -2)
            {
                fprintf(stderr, "Config file support not enabled (not using libxslt & libxml2)\n");
                exit(1);
            }
            else if (err == -1)
            {
                fprintf(stderr, "Bad or missing file %s\n", arg);
                exit(1);
            }
            break;
        case 'D':
            daemon_flags |= YAZ_DAEMON_FORK;
            break;
        case 'i':
            proxy->set_client_idletime(atoi(arg));
            break;
        case 'l':
            yaz_log_init_file (arg);
            log_file = xstrdup(arg);
            break;
        case 'm':
            proxy->set_max_clients(atoi(arg));
            break;
        case 'n':
            no_limit_files = atoi(arg);
            break;
        case 'o':
            proxy->option("optimize", arg);
            break;
        case 'p':
            if (!pid_fname)
                pid_fname = xstrdup(arg);
            break;
        case 't':
            proxy->set_default_target(arg);
            break;
        case 'T':
            proxy->set_target_idletime(atoi(arg));
            break;
        case 'u':
            if (!uid)
                uid = xstrdup(arg);
            break;
        case 'v':
            yaz_log_init_level (yaz_log_mask_str(arg));
            break;
        case 'V':
            puts(
#ifdef VERSION
                VERSION
#else
                "unknown"
#endif
                );
            exit(0);
        case 'X':
            proxy->set_debug_mode(1);
            daemon_flags = YAZ_DAEMON_DEBUG;
            break;
        default:
            usage(prog);
            return 1;
        }
    }
    if (addr)
    {
        if (proxy->server(addr))
        {
            yaz_log(YLOG_FATAL|YLOG_ERRNO, "listen %s", addr);
            exit(1);
        }
    }
    else
    {
        usage(prog);
        return 1;
    }
    return 0;
}

static Yaz_Proxy *static_yaz_proxy = 0;
static void sighup_handler(int num)
{
#if WIN32
#else
    signal(SIGHUP, sighup_handler);
#endif
    if (static_yaz_proxy)
        static_yaz_proxy->reconfig();
}

#if YAZ_HAVE_XSLT
static void proxy_xml_error_handler(void *ctx, const char *fmt, ...)
{
    char buf[1024];

    va_list ap;
    va_start(ap, fmt);

#ifdef WIN32
    vsprintf(buf, fmt, ap);
#else
    vsnprintf(buf, sizeof(buf), fmt, ap);
#endif
    yaz_log(YLOG_WARN, "%s: %s", (char*) ctx, buf);

    va_end (ap);
}
#endif

static void child_run(void *data)
{
    SocketManager *m = (SocketManager *) data;
#ifdef WIN32
#else
    signal(SIGHUP, sighup_handler);
#endif

#if YAZ_HAVE_XSLT
    xmlSetGenericErrorFunc((void *) "XML", proxy_xml_error_handler);
    xsltSetGenericErrorFunc((void *) "XSLT", proxy_xml_error_handler);
#endif

#if YAZ_HAVE_EXSLT
    exsltRegisterAll();
#endif
#ifdef WIN32
#else
    yaz_log(YLOG_LOG, "0 proxy pid=%ld", (long) getpid());
#endif
    if (no_limit_files)
    {
#if HAVE_SETRLIMIT
        struct rlimit limit_data;
        limit_data.rlim_cur = no_limit_files;
        limit_data.rlim_max = no_limit_files;
        
        yaz_log(YLOG_LOG, "0 setrlimit NOFILE cur=%ld max=%ld",
                (long) limit_data.rlim_cur, (long) limit_data.rlim_max);
        if (setrlimit(RLIMIT_NOFILE, &limit_data))
            yaz_log(YLOG_ERRNO|YLOG_WARN, "setrlimit");
#else
        yaz_log(YLOG_WARN, "setrlimit unavablable. Option -n ignored");
#endif
    }
#if HAVE_GETRLIMIT
    struct rlimit limit_data;
    getrlimit(RLIMIT_NOFILE, &limit_data);
    yaz_log(YLOG_LOG, "0 getrlimit NOFILE cur=%ld max=%ld",
            (long) limit_data.rlim_cur, (long) limit_data.rlim_max);
#endif
    
    while (m->processEvent() > 0)
        ;

    exit (0);
}

int main(int argc, char **argv)
{
#if YAZ_HAVE_XSLT
    xmlInitMemory();
    
    LIBXML_TEST_VERSION
#endif
    SocketManager mySocketManager;
    Yaz_Proxy proxy(new PDU_Assoc(&mySocketManager), &mySocketManager);

    static_yaz_proxy = &proxy;

    args(&proxy, argc, argv);

    yaz_daemon("yazproxy", daemon_flags,
               child_run, &mySocketManager, pid_fname, uid);
    exit (0);
    return 0;
}
/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

