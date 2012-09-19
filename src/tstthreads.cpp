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

#include <stdlib.h>
#include <ctype.h>

#include <yazpp/pdu-assoc.h>
#include <yazpp/socket-manager.h>
#include <yaz/log.h>
#include "msg-thread.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

using namespace yazpp_1;

class My_Msg : public IMsg_Thread {
public:
    IMsg_Thread *handle();
    void result();
    int m_val;
};

IMsg_Thread *My_Msg::handle()
{
    My_Msg *res = new My_Msg;
    int sl = rand() % 5;

    res->m_val = m_val;
    printf("My_Msg::handle val=%d sleep=%d\n", m_val, sl);
#if HAVE_UNISTD_H
    sleep(sl);
#endif
    return res;
}

void My_Msg::result()
{
    printf("My_Msg::result val=%d\n", m_val);
}

class My_Timer_Thread : public ISocketObserver {
private:
    ISocketObservable *m_obs;
    int m_fd[2];
    Msg_Thread *m_t;
public:
    My_Timer_Thread(ISocketObservable *obs, Msg_Thread *t);
    void socketNotify(int event);
};

My_Timer_Thread::My_Timer_Thread(ISocketObservable *obs,
                                 Msg_Thread *t) : m_obs(obs)
{
    pipe(m_fd);
    m_t = t;
    obs->addObserver(m_fd[0], this);
    obs->maskObserver(this, SOCKET_OBSERVE_READ);
    obs->timeoutObserver(this, 1);
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
    SocketManager mySocketManager;

    Msg_Thread m(&mySocketManager, 3);
    My_Timer_Thread t(&mySocketManager, &m) ;
    int i = 0;
    while (++i < 5 && mySocketManager.processEvent() > 0)
        ;
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

