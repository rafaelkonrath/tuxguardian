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





#include "main.h"

// stuff needed to put the systray icon
#include "trayicon.h"
#include "tg-icon.xpm"
#include <qpixmap.h>
#include <qpopupmenu.h>
#include <qmainwindow.h>


#include <qapplication.h>
#include <unistd.h>

#include <qpushbutton.h>

#include <qsocketnotifier.h>
#include <qcheckbox.h>
#include <qapplication.h>
#include <qvbox.h>
#include <qtextview.h>
#include <qlabel.h>
#include <qpushbutton.h>
#include <qtextstream.h>
#include <stdlib.h>


#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>

#include <iostream>


using std::cout;
using std::endl;


//-----------------------------------------------------------------------------
myForm::myForm( QWidget* parent, const char* name, bool modal, WFlags fl )
    : Form2( parent, name, modal, fl )
{
}	
//-----------------------------------------------------------------------------



//-----------------------------------------------------------------------------
myForm::~myForm()
{
}
//-----------------------------------------------------------------------------




//-----------------------------------------------------------------------------
void myForm::read_query()
{
    struct tg_query received;
    char hash[40];
    char file_path[4096];
    int retval=-1;
    
    retval =  recv(socket, &received, sizeof(struct tg_query), MSG_WAITALL);
    
    
    // saves the incoming query
    received_query.sender 		= received.sender;
    received_query.seqno 		= received.seqno;
    received_query.query_type 	= received.query_type;
    received_query.query_data 	= received.query_data;
    
    printf("\n\n    Query from daemon wants to know if\n");
    if (received.query_type == TG_ASK_PERMIT_APP) {
      printf("       PERMIT_APP ");
      attentionText->setPaletteForegroundColor( QColor( 85, 85, 225 ) );	      
      warningText->setText("An unauthorized application is trying to ACCESS THE INTERNET!");
  }
    else {
	if (received.query_type == TG_PERMIT_SERVER) {
	printf("       PERMIT_SERVER ");
	attentionText->setPaletteForegroundColor( QColor( 170, 0, 0 ) );		
	warningText->setText("An unauthorized application is trying to ACT LIKE A SERVER!");
    }
      else
	printf("       -- oops. Invalid query type: %d\n", received.query_type);
    }
    
    
    // prepares the answer
    answer.sender		= TG_FRONTEND;
    answer.seqno		= received.seqno;
    // actually the query_type depends on the received.query_type
    answer.query_type 	= TG_RESPOND_PERMIT_APP;
    
    // query_data is going to be filled when the user clicks the chosen button
    if ( calc_md5(received.query_data, hash, file_path) == -1) {
	printf("\n    Could not calculate the md5hash!\n");
	answer.query_data = NO_ERROR_IN_FRONTEND;
	
	// respond with error and leave!
	write(socket, &answer, sizeof(tg_query));
	close();
	return;
    }

    appname->setText(QString(file_path));
    apphash->setText(QString(hash));
    printf("%s\n       with hash %s", file_path, hash);
    
}
//-----------------------------------------------------------------------------




//-----------------------------------------------------------------------------
void myForm::sendAnswer()
{
    QPushButton *b;
    b = (QPushButton *) sender();
    
    printf("\n    Responding ");
     
    if ((b->text())=="ok") {
	if (save_in_file->isChecked()) {
	    answer.query_data = YES_SAVE_IN_FILE;
	    printf(" OK and save in file!\n");	    
	}
	else {
	    answer.query_data = YES;
	printf(" OK!\n");	    
	}
    }
    else {
	if ((b->text())=="deny") {
	    if (save_in_file->isChecked()) {
		answer.query_data = NO_SAVE_IN_FILE;
		printf(" DENY and save in file!\n");
	    }
	    else {
		answer.query_data = NO_USER_FORBID;
		printf(" DENY!\n");
	    }
	}
	else {
	    printf("    OOPS. Bad button!\n");
	    answer.query_data = NO_ERROR_IN_FRONTEND;
	}
    }
    
//    printf("enviando: sender: %d   seqno: %d    query_type: %d    query_data:  %d\n", 
//	   (int)answer.sender, answer.seqno, 
//	   (int)answer.query_type, answer.query_data);

    write(socket, &answer, sizeof(struct tg_query));
    close();
}
//-----------------------------------------------------------------------------





//-----------------------------------------------------------------------------
SimpleServerX ::SimpleServerX( QObject* parent=0 ) :
	QServerSocket( parent, 0 )
	{
    int server_sockfd;
    int server_len;
    struct sockaddr_un server_address;
    
    unlink(DAEMON_PATH);
    server_sockfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    
    // make the socket non blocking
    fcntl(server_sockfd,F_SETFL,O_NONBLOCK);  
    
    /*  Name the socket.  */
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, DAEMON_PATH);
    server_len = sizeof(server_address);
    printf("Binding %s\n", server_address.sun_path);
    int k=bind(server_sockfd, (struct sockaddr *)&server_address, server_len);
    if (k == -1) {
	perror("Could not bind to the socket!\n");
	exit(1);
    }	
    
    /*  Create a connection queue and wait for clients.  */
    listen(server_sockfd, 1024);
    
    printf("Waiting for daemon queries...\n");	
    setSocket(server_sockfd);
}
//-----------------------------------------------------------------------------





//-----------------------------------------------------------------------------
SimpleServerX::~SimpleServerX()
{
}
//-----------------------------------------------------------------------------




//-----------------------------------------------------------------------------

void SimpleServerX::newConnection( int socket )
{
    
    myForm *w = new myForm();
    
   
    w -> socket = socket;
    w -> read_query();
    
    // send the answer when a button is clicked
    connect (w->buttonOK, SIGNAL(clicked()), w, SLOT(sendAnswer()));
    connect (w->buttonDeny, SIGNAL(clicked()), w, SLOT(sendAnswer()));	
   
    w->show();
}
//-----------------------------------------------------------------------------



//-----------------------------------------------------------------------------
int calc_md5(pid_t pid, char *hash, char *real_path) 
{
    
    FILE *file;
    int err, i;
    
    char tmphash[40], tmp[10];
    char link_path[4096]="/proc/";
    
    sprintf(tmp, "%d", pid);
    strcat(link_path, tmp);
    strcat(link_path, "/exe");
    
    
//    printf("calc_md5 pro link %s\n", link_path);
    if ((err=readlink(link_path, real_path, 4096)) == -1) {
	perror("    Error on trying to readlink() /proc: ");
	
	// debugging info is commented (calling system is dangerous!)
	// 	printf("\n     Debugging with 'system..'\n");
	// 	strcpy(link_path, "readlink /proc/");
	// 	sprintf(tmp, "%d", pid);
	// 	strcat(link_path, tmp);
	// 	strcat(link_path, "/exe");
// 	system(link_path);
	return -1;
    }
    // readlink does not append a NUL  character
    real_path[err]='\0';
    
//    printf("real_path: %s\n", real_path);
    
    if ((file = fopen(real_path, "r")) == NULL) { 
	perror("    Error on trying to fopen() /proc: ");
	return -1;
    }
    
    md5_stream (file, tmphash);
    
    // convert the hash returned by md5_stream into a valid string
    hash[0]='\0';
    tmp[0]='\0';
    for (i = 0; i < 16; i++) {
	sprintf(tmp, "%02x", tmphash[i] & 0xff);
	strcat(hash, tmp);
    }
    hash[32]='\0';  // to form a valid NULL terminated string
   
    fclose(file);
    return 0;
}
//-----------------------------------------------------------------------------






int main(int argc, char **argv) {
    

  // makes the frontend run in background automatically
  int pid = fork();
  if (pid == -1) {
    perror("Fork error...\n");
    exit(1);
  }
  if (pid != 0) {
    exit(0); // this is the parent, hence should exit
  }
  
  
  QApplication app(argc, argv);
  
  //   uid_t ruid, euid, rgid, egid;
  //   ruid = getuid();
  //   euid = geteuid();
  //   rgid = getgid();
  //   egid = getegid();
  //printf("user id = %d   effective uid = %d     group id = %d    effective gid = %d\n", ruid, euid, rgid, egid);
  
  // initializes the systray icon
  QPopupMenu menu;
  //     menu.insertItem( "Option A", &mw, SLOT(showNormal()) );
  //     menu.insertItem( "Option B", &mw, SLOT(showMinimized()) );
  //     menu.insertSeparator();
  menu.insertItem( "&Quit", &app, SLOT(quit()));
  TrayIcon tray( QPixmap( (const char**)tg_icon_xpm ), "TuxGuardian running...", &menu );
  tray.show();
  
  // initializes the server that will receive the daemon's queries
  SimpleServerX server(NULL);  
  
  // run!
  return app.exec();
  
}
