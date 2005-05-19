/* $Id: tstthreads.cpp,v 1.1 2005-05-19 21:29:58 adam Exp $
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

#include <pthread.h>
#include <unistd.h>
#include <ctype.h>

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <yaz++/socket-observer.h>
#include <yaz++/socket-manager.h>
#include <yaz/log.h>
#include "proxyp.h"

class Proxy_Msg {
public:
    virtual void destroy() = 0;
    virtual Proxy_Msg *handle() = 0;
    virtual void result() = 0;
};

class Proxy_Msg_Queue_List {
    friend class Proxy_Msg_Queue;
 private:
    Proxy_Msg *m_item;
    Proxy_Msg_Queue_List *m_next;
};

class Proxy_Msg_Queue {
 public:
    Proxy_Msg_Queue();
    void enqueue(Proxy_Msg *in);
    Proxy_Msg *dequeue();
    int size();
 private:
    Proxy_Msg_Queue_List *m_list;
};

Proxy_Msg_Queue::Proxy_Msg_Queue()
{
    m_list = 0;
}

int Proxy_Msg_Queue::size()
{
    int no = 0;
    Proxy_Msg_Queue_List *l;
    for (l = m_list; l; l = l->m_next)
        no++;
    return no;
}

void Proxy_Msg_Queue::enqueue(Proxy_Msg *m)
{
    Proxy_Msg_Queue_List *l = new Proxy_Msg_Queue_List;
    l->m_next = m_list;
    l->m_item = m;
    m_list = l;
}

Proxy_Msg *Proxy_Msg_Queue::dequeue()
{
    Proxy_Msg_Queue_List **l = &m_list;
    if (!*l)
        return 0;
    while ((*l)->m_next)
	l = &(*l)->m_next;
    Proxy_Msg *m = (*l)->m_item;
    delete *l;
    *l = 0;
    return m;
}

class Proxy_Thread : public IYazSocketObserver {
public:
    Proxy_Thread(IYazSocketObservable *obs);
    virtual ~Proxy_Thread();
    void socketNotify(int event);
    void put(Proxy_Msg *m);
    Proxy_Msg *get();
    void run(void *p);
private:
    IYazSocketObservable *m_obs;
    int m_fd[2];
    pthread_t m_thread_id;
    Proxy_Msg_Queue m_input;
    Proxy_Msg_Queue m_output;
    pthread_mutex_t m_mutex_input_data;
    pthread_cond_t m_cond_input_data;
    pthread_mutex_t m_mutex_output_data;
    pthread_cond_t m_cond_output_data;
};

static void *tfunc(void *p)
{
    Proxy_Thread *pt = (Proxy_Thread *) p;
    pt->run(0);
    return 0;
}


Proxy_Thread::Proxy_Thread(IYazSocketObservable *obs)
    : m_obs(obs)
{
    pthread_mutex_init(&m_mutex_input_data, 0);
    pthread_cond_init(&m_cond_input_data, 0);
    pthread_mutex_init(&m_mutex_output_data, 0);
    pthread_cond_init(&m_cond_output_data, 0);
    m_fd[0] = m_fd[1] = -1;
    if (pipe(m_fd) != 0)
	return;
    m_obs->addObserver(m_fd[0], this);
    m_obs->timeoutObserver(this, 2000);
    m_obs->maskObserver(this, YAZ_SOCKET_OBSERVE_READ);

    pthread_create(&m_thread_id, 0, tfunc, this);
}

Proxy_Thread::~Proxy_Thread()
{

}

void Proxy_Thread::socketNotify(int event)
{
    char buf[2];
    read(m_fd[0], buf, 1);
    pthread_mutex_lock(&m_mutex_output_data);
    Proxy_Msg *out = m_output.dequeue();
    pthread_mutex_unlock(&m_mutex_output_data);
    if (out)
	out->result();
}

void Proxy_Thread::run(void *p)
{
    while(1)
    {
	pthread_mutex_lock(&m_mutex_input_data);
	pthread_cond_wait(&m_cond_input_data, &m_mutex_input_data);
	while(1)
	{
	    Proxy_Msg *in = m_input.dequeue();
	    pthread_mutex_unlock(&m_mutex_input_data);
	    if (!in)
		break;
	    Proxy_Msg *out = in->handle();
	    pthread_mutex_lock(&m_mutex_output_data);
	    m_output.enqueue(out);
	    pthread_cond_signal(&m_cond_output_data);
	    pthread_mutex_unlock(&m_mutex_output_data);
	    write(m_fd[1], "", 1);

	    pthread_mutex_lock(&m_mutex_input_data);
	}
    }
}

void Proxy_Thread::put(Proxy_Msg *m)
{
    pthread_mutex_lock(&m_mutex_input_data);
    m_input.enqueue(m);
    pthread_cond_signal(&m_cond_input_data);
    int in_size = m_input.size();
    pthread_mutex_unlock(&m_mutex_input_data);
    int out_size = m_output.size();
    printf("in-size=%d out-size=%d\n", in_size, out_size);
}

class My_Msg : public Proxy_Msg {
public:
    void destroy();
    Proxy_Msg *handle();
    void result();
    int m_val;
};

class My_Thread : public Proxy_Thread {
public:
    My_Thread(IYazSocketObservable *obs);
};

My_Thread::My_Thread(IYazSocketObservable *obs) : Proxy_Thread(obs)
{
}

Proxy_Msg *My_Msg::handle()
{
    My_Msg *res = new My_Msg;
    int sl = rand() % 5;

    res->m_val = m_val;
    printf("My_Msg::handle val=%d sleep=%d\n", m_val, sl);
    sleep(sl);
    return res;
}


void My_Msg::result()
{
    printf("My_Msg::result val=%d\n", m_val);
}

void My_Msg::destroy()
{
    delete this;
}

class My_Timer_Thread : public IYazSocketObserver {
private:
    IYazSocketObservable *m_obs;
    int m_fd[2];
    My_Thread *m_t;
public:
    My_Timer_Thread(IYazSocketObservable *obs, My_Thread *t);
    void socketNotify(int event);
};

My_Timer_Thread::My_Timer_Thread(IYazSocketObservable *obs,
				 My_Thread *t) : m_obs(obs) 
{
    pipe(m_fd);
    m_t = t;
    obs->addObserver(m_fd[0], this);
    obs->timeoutObserver(this, 2);
}

void My_Timer_Thread::socketNotify(int event)
{
    static int seq = 1;
    printf("Add %d\n", seq);
    My_Msg *m = new My_Msg;
    m->m_val = seq++;
    m_t->put(m);
}

int main(int argc, char **argv)
{
    Yaz_SocketManager mySocketManager;

    My_Thread m(&mySocketManager);
    My_Timer_Thread t(&mySocketManager, &m);
    while (mySocketManager.processEvent() > 0)
	;
    return 0;
}
