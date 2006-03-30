/* $Id: msg-thread.h,v 1.11 2006-03-30 14:16:34 adam Exp $
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

#include <yazpp/socket-observer.h>
#include <yaz/yconfig.h>

class YAZ_EXPORT IMsg_Thread {
public:
    virtual IMsg_Thread *handle() = 0;
    virtual void result() = 0;
    virtual ~IMsg_Thread();
};

class YAZ_EXPORT Msg_Thread_Queue_List {
    friend class Msg_Thread_Queue;
 private:
    IMsg_Thread *m_item;
    Msg_Thread_Queue_List *m_next;
};

class YAZ_EXPORT Msg_Thread_Queue {
 public:
    Msg_Thread_Queue();
    void enqueue(IMsg_Thread *in);
    IMsg_Thread *dequeue();
    int size();
 private:
    Msg_Thread_Queue_List *m_list;
};

class YAZ_EXPORT Msg_Thread : public yazpp_1::ISocketObserver {
    class Private;
 public:
    Msg_Thread(yazpp_1::ISocketObservable *obs, int no_threads);
    virtual ~Msg_Thread();
    void socketNotify(int event);
    void put(IMsg_Thread *m);
    IMsg_Thread *get();
    void run(void *p);
private:
    class Private *m_p;
};

/*
 * Local variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 * vim: shiftwidth=4 tabstop=8 expandtab
 */

