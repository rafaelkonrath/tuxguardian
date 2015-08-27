/*
    TuxGuardian is copyright 2004, Bruno Castro da Silva (brunocs@portoweb.com.br)
                                   http://tuxguardian.sourceforge.net

    This file is part of TuxGuardian.

    TuxGuardian is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    TuxGuardian is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TuxGuardian; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/




#ifndef __HAS_TG_DEFS_H
#define __HAS_TG_DEFS_H

#include <asm/types.h>
#include <qsocket.h>
#include <qserversocket.h>

#include "ask.h"

extern "C" {
#include "md5.h"
}

struct tg_query {
    __u8 sender;
    __u32 seqno;   // sequence number
    __u8 query_type;
    __u32 query_data;
};


#define DAEMON_PATH "/tmp/tux_frontend_server"

// sender
#define TG_MODULE 0
#define TG_DAEMON 1
#define TG_FRONTEND 2

// query_type
#define TG_ASK_PERMIT_APP 0
#define TG_RESPOND_PERMIT_APP 1
#define TG_PERMIT_REMOVE_MODULE 2
#define TG_PERMIT_ACCESS_FILE 3
#define TG_PERMIT_SERVER 4
#define TG_RESPOND_PERMIT_SERVER 5

// RESPOND_PERMIT_APP possibilities
#define YES 0
#define YES_SAVE_IN_FILE 6
#define NO_ACCESS_IS_DENIED 7
#define NO_SAVE_IN_FILE 8
#define NO_WRONG_HASH 1
#define NO_NOT_IN_HASHTABLE 2
#define NO_ERROR_IN_DAEMON 3
#define NO_USER_FORBID 4
#define NO_ERROR_IN_FRONTEND 5

int calc_md5(pid_t pid, char *hash, char *real_path);


class myForm: public Form2
{
    Q_OBJECT
    public:
    struct tg_query received_query;
    struct tg_query answer;

    int socket;
    
    void read_query();
    myForm(QWidget* parent = 0, const char* name = 0, bool modal = FALSE, WFlags fl = 0 );
    ~myForm();
    
    public slots:	
	    void sendAnswer();

} ;






class SimpleServerX : public QServerSocket
{
    Q_OBJECT
    
    public:
    
    SimpleServerX( QObject* parent );
    ~SimpleServerX();
    
    void newConnection( int socket );
};



#endif
