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

#if YAZ_POSIX_THREADS
#include <pthread.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>

#include <yazpp/socket-observer.h>
#include <yaz/log.h>

#include "msg-thread.h"

using namespace yazpp_1;

class Msg_Thread::Private {
public:
    int m_no_threads;
    Msg_Thread_Queue m_input;
    Msg_Thread_Queue m_output;
#if YAZ_POSIX_THREADS
    int m_fd[2];
    yazpp_1::ISocketObservable *m_SocketObservable;
    pthread_t *m_thread_id;
    pthread_mutex_t m_mutex_input_data;
    pthread_cond_t m_cond_input_data;
    pthread_mutex_t m_mutex_output_data;
    bool m_stop_flag;
#endif
};

IMsg_Thread::~IMsg_Thread()
{

}

Msg_Thread_Queue::Msg_Thread_Queue()
{
    m_list = 0;
}

int Msg_Thread_Queue::size()
{
    int no = 0;
    Msg_Thread_Queue_List *l;
    for (l = m_list; l; l = l->m_next)
        no++;
    return no;
}

void Msg_Thread_Queue::enqueue(IMsg_Thread *m)
{
    Msg_Thread_Queue_List *l = new Msg_Thread_Queue_List;
    l->m_next = m_list;
    l->m_item = m;
    m_list = l;
}

IMsg_Thread *Msg_Thread_Queue::dequeue()
{
    Msg_Thread_Queue_List **l = &m_list;
    if (!*l)
        return 0;
    while ((*l)->m_next)
        l = &(*l)->m_next;
    IMsg_Thread *m = (*l)->m_item;
    delete *l;
    *l = 0;
    return m;
}

#if YAZ_POSIX_THREADS
static void *tfunc(void *p)
{
    Msg_Thread *pt = (Msg_Thread *) p;
    pt->run(0);
    return 0;
}
#endif

Msg_Thread::Msg_Thread(ISocketObservable *obs, int no_threads)
{
    m_p = new Private;

#if YAZ_POSIX_THREADS
    m_p->m_SocketObservable = obs;

    pipe(m_p->m_fd);
    obs->addObserver(m_p->m_fd[0], this);
    obs->maskObserver(this, SOCKET_OBSERVE_READ);

    m_p->m_stop_flag = false;
    pthread_mutex_init(&m_p->m_mutex_input_data, 0);
    pthread_cond_init(&m_p->m_cond_input_data, 0);
    pthread_mutex_init(&m_p->m_mutex_output_data, 0);

    m_p->m_no_threads = no_threads;
    m_p->m_thread_id = new pthread_t[no_threads];
    int i;
    for (i = 0; i<m_p->m_no_threads; i++)
        pthread_create(&m_p->m_thread_id[i], 0, tfunc, this);
#endif
}

Msg_Thread::~Msg_Thread()
{
#if YAZ_POSIX_THREADS
    pthread_mutex_lock(&m_p->m_mutex_input_data);
    m_p->m_stop_flag = true;
    pthread_cond_broadcast(&m_p->m_cond_input_data);
    pthread_mutex_unlock(&m_p->m_mutex_input_data);
    
    int i;
    for (i = 0; i<m_p->m_no_threads; i++)
        pthread_join(m_p->m_thread_id[i], 0);
    delete [] m_p->m_thread_id;

    m_p->m_SocketObservable->deleteObserver(this);

    pthread_cond_destroy(&m_p->m_cond_input_data);
    pthread_mutex_destroy(&m_p->m_mutex_input_data);
    pthread_mutex_destroy(&m_p->m_mutex_output_data);
    close(m_p->m_fd[0]);
    close(m_p->m_fd[1]);
#endif

    delete m_p;
}

void Msg_Thread::socketNotify(int event)
{
#if YAZ_POSIX_THREADS
    if (event & SOCKET_OBSERVE_READ)
    {
        char buf[2];
        read(m_p->m_fd[0], buf, 1);
        pthread_mutex_lock(&m_p->m_mutex_output_data);
        IMsg_Thread *out = m_p->m_output.dequeue();
        pthread_mutex_unlock(&m_p->m_mutex_output_data);
        if (out)
            out->result();
    }
#endif
}

#if YAZ_POSIX_THREADS
void Msg_Thread::run(void *p)
{
    while(1)
    {
        pthread_mutex_lock(&m_p->m_mutex_input_data);
        while (!m_p->m_stop_flag && m_p->m_input.size() == 0)
            pthread_cond_wait(&m_p->m_cond_input_data, &m_p->m_mutex_input_data);
        if (m_p->m_stop_flag)
        {
            pthread_mutex_unlock(&m_p->m_mutex_input_data);
            break;
        }
        IMsg_Thread *in = m_p->m_input.dequeue();
        pthread_mutex_unlock(&m_p->m_mutex_input_data);

        IMsg_Thread *out = in->handle();
        pthread_mutex_lock(&m_p->m_mutex_output_data);
        m_p->m_output.enqueue(out);
        
        write(m_p->m_fd[1], "", 1);
        pthread_mutex_unlock(&m_p->m_mutex_output_data);
    }
}
#endif

void Msg_Thread::put(IMsg_Thread *m)
{
#if YAZ_POSIX_THREADS
    pthread_mutex_lock(&m_p->m_mutex_input_data);
    m_p->m_input.enqueue(m);
    pthread_cond_signal(&m_p->m_cond_input_data);
    pthread_mutex_unlock(&m_p->m_mutex_input_data);
#else
    IMsg_Thread *out = m->handle();
    if (out)
        out->result();
#endif
}
/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

