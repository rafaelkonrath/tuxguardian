#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>

#include <ask.h>

using std::cout;
using std::endl;


/****************************************************************************
** ui.h extension file, included from the uic-generated form implementation.
**
** If you wish to add, delete or rename functions or slots use
** Qt Designer which will update this file, preserving your code. Create an
** init() function in place of a constructor, and a destroy() function in
** place of a destructor.
*****************************************************************************/
void le_sock()
{

    int server_sockfd, client_sockfd;
    int server_len, client_len;
    struct sockaddr_un server_address;
    struct sockaddr_un client_address;

    unlink("/tmp/daemon_socket");
    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    /*  Name the socket.  */

    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, "/tmp/daemon_socket");
    server_len = sizeof(server_address);
    bind(server_sockfd, (struct sockaddr *)&server_address, server_len);

    /*  Create a connection queue and wait for clients.  */

    listen(server_sockfd, 5);
    char ch;
  
    printf("server waiting\n");
  
    /*  Accept a connection.  */
  
    client_len = sizeof(client_address);
    client_sockfd = accept(server_sockfd, 
			   (struct sockaddr *)&client_address,  (socklen_t *)&client_len);
  
    /*  We can now read/write to client on client_sockfd.  */
  
    read(client_sockfd, &ch, 1);
    printf("leu %c!!\n", ch);


    //     setCaption( tr( "TuxGuardian" ) );
    //     textLabel3->setText( tr( "An unauthorized application is trying to ACCESS THE INTERNET!" ) );
    //     textLabel5->setText( tr( "MD5Hash" ) );
    //     textLabel4->setText( tr( "Application" ) );
    //     pushButton3->setText( tr( "just for now" ) );
    //     pushButton2->setText( tr( "deny" ) );
    //     pushButton1->setText( tr( "ok" ) );
    //     textLabel2->setText( tr( "ATTENTION!" ) );

    ch++;
    write(client_sockfd, &ch, 1);
    close(client_sockfd);

}


void Form3::init()
{
   Form2 *w;
  //    printf("init! meu caption eh %s\n", caption());
  cout << "FORM3 init! meu caption eh " << caption() << endl;
  
  while (1) {
  le_sock();
    w = new Form2();
    w->show();
   }
  	
}
