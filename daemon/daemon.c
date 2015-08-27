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








#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <string.h> 
#include <fcntl.h>
#include <sys/types.h>   //  constants in chmod
#include <sys/stat.h>
#include <asm/types.h>   //  __u8, etc
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>		// to trap the SIGALRM signal
#include <stdlib.h>


#include "pbl.h"


#define PATH_MODULE "/tmp/tux_daemon_server"
#define PATH_FRONTEND "/tmp/tux_frontend_server"
#define DAEMON_CONF "/etc/daemon.conf"

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
#define NO_ACCESS_IS_DENIED 7  // deny because the user said NO by means of daemon.conf
#define NO_SAVE_IN_FILE 8      // deny beucase the user said NO, and save this info on daemon.conf
#define NO_WRONG_HASH 1
#define NO_NOT_IN_HASHTABLE 2  // deny because we don't have the needed information about the app
#define NO_ERROR_IN_DAEMON 3
#define NO_USER_FORBID 4       // deny because the user said NO by means of the frontend
#define NO_ERROR_IN_FRONTEND 5

// daemon.conf permissions
#define SET_HAS_INFO_PERMIT_APP(opts) opts = opts | 4
#define SET_HAS_INFO_PERMIT_SERVER(opts) opts = opts | 8
#define UNSET_HAS_INFO_PERMIT_APP(opts) opts = opts & 0xfffffb
#define UNSET_HAS_INFO_PERMIT_SERVER(opts) opts = opts & 0xfffff7
#define ISSET_HAS_INFO_PERMIT_APP(opts) (opts & 4)
#define ISSET_HAS_INFO_PERMIT_SERVER(opts) (opts & 8)

#define SET_PERMIT_APP(opts) opts = opts | 1
#define SET_DENY_APP(opts) opts = opts & 0xfffffe
#define SET_PERMIT_SERVER(opts) opts = opts | 2
#define SET_DENY_SERVER(opts) opts = opts & 0xfffffd
#define ISSET_PERMIT_APP(opts) (opts & 1)
#define ISSET_DENY_APP(opts) !(opts & 1)
#define ISSET_PERMIT_SERVER(opts) (opts & 2)
#define ISSET_DENY_SERVER(opts) !(opts & 2)
#define PERMIT_APP "PERMIT_APP"
#define PERMIT_SERVER "PERMIT_SERVER"
#define DENY_APP "DENY_APP"
#define DENY_SERVER "DENY_SERVER"

#define MD5HASH_SIZE 40   // actually it's 32, but i'm paranoid
#define MAX_LINE_LENGTH 4096



pblHashTable_t *ht;  // the hashtable where we keep info on the app's permissions

// sets whether the daemon should only print the module's queries,
// instead of processing them and checking for security information
int generate_first_config_file=0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;



struct tg_query {
  __u8 sender;
  __u32 seqno;   // sequence number
  __u8 query_type;
  __u32 query_data;
};

struct hashtable_record {
  char md5hash[MD5HASH_SIZE];
  __u32 opts;   // options, like PERMIT_APP, DENY_SERVER, etc
};


// this struct encapsulates the received tg_query and the socket
// that'll be used by the thread to communicate with the kernel module
struct data_to_process {
  struct tg_query query;
  int sock;
};



int update_file(char query_type, int frontend_answer, char *app_path, char *md5hash);
int analyse_frontend_answer(char query_type, int frontend_answer, 
			    char *md5hash, char *app_path);
int try_ask_the_user(struct tg_query module_query, char *hash, char *file_path);
int check_app_permissions(struct tg_query module_query, int app_permissions, 
			  char *hash, char *file_path);
void *process_module_query(void *data);
int forward_query_to_frontend(struct tg_query query);
int calc_md5(pid_t pid, char *hash, char *real_path);
int insert_in_hash(char *path, struct hashtable_record *ht_record);
int parse_app_opts(char *app_opts, int verbose_mode);
int init_hash();
int verify_app_in_hash(char *path, char *md5hash);
int remove_from_hash(char *path, char *md5hash);
int delete_hash_table();



//--------------------------------------------------------------------------------
int update_file(char query_type, int frontend_answer, char *app_path, char *md5hash)
{
  char line[MAX_LINE_LENGTH], permissions[MAX_LINE_LENGTH];
  int temp_fd, retval;
  FILE *daemon_file, *temp_file;
  int opts, has_updated = 0;

  char temp_file_path[400];

  if ((daemon_file = fopen(DAEMON_CONF, "r")) == NULL) {
    printf("      OOPS. Could not open daemon_conf\n");
    return -1;
  }


  // creates a temporary file
  strcpy(temp_file_path, "/tmp/tuxtmpXXXXXXXX");
  temp_fd = mkstemp(temp_file_path);
  if (temp_fd == -1) {
    printf("      OOPS. Could not open temporary file while updating %s \n", DAEMON_CONF);
    return -1;
  }

  if ((temp_file = fdopen(temp_fd, "r")) == NULL) {
    printf("      OOPS. Could not stream-open the temporary file\n");
    return -1;
  }



  // prepares string with new permission
  permissions[0]='\0';
  switch(query_type) {
    
  case TG_ASK_PERMIT_APP:
    if (frontend_answer == YES)
      strcat(permissions, "PERMIT_APP ");
    else
      strcat(permissions, "DENY_APP ");
    break;

  case TG_PERMIT_SERVER:
    if (frontend_answer == YES)
      strcat(permissions, "PERMIT_SERVER ");
    else
      strcat(permissions, "DENY_SERVER ");
    break;
	
  default:
    printf("      Trying to update file with unknown permissions (%d)!\n", frontend_answer);
    return NO_ERROR_IN_DAEMON;
  }

  

  // writes the updated daemon_conf to the temporary file
  while (1) {
    fgets (line, MAX_LINE_LENGTH, daemon_file);
    if (feof (daemon_file))
      break;
    line[strlen(line)-1]='\0';

    if (!strcmp(line, app_path)) {
      
      // writes the app path to the temporary file
      write(temp_fd, line, strlen(line));
      write(temp_fd, "\n", 1);

      // writes the app's md5hash to the temporary file
      fgets(line, MAX_LINE_LENGTH, daemon_file);
      write(temp_fd, line, strlen(line));

      // reads the line with the current permissions
      fgets(line, MAX_LINE_LENGTH, daemon_file);
      line[strlen(line)-1]='\0';
      
      // reads the current permissions to a string
      opts = parse_app_opts(line, 0);
      line[0]='\0';
      if (ISSET_HAS_INFO_PERMIT_APP(opts))
	if (ISSET_PERMIT_APP(opts)) {
	  strcat(line, "PERMIT_APP ");
	}
	else {
	  strcat(line, "DENY_APP ");
	}

      if (ISSET_HAS_INFO_PERMIT_SERVER(opts))
	if (ISSET_PERMIT_SERVER(opts)) {
	  strcat(line, "PERMIT_SERVER ");
	}
	else {
	  strcat(line, "DENY_SERVER ");
	}
      
      strcat(line, permissions);
      has_updated=1;

    }

    // writes the permissions
    write(temp_fd, line, strlen(line));
    write(temp_fd, "\n", 1);

  }

  // daemon_conf didn't have any record to this app, so we insert it now
  if (!has_updated) {
    write(temp_fd, app_path, strlen(app_path));
    write(temp_fd, "\n", 1);
    write(temp_fd, md5hash, strlen(md5hash));
    write(temp_fd, "\n", 1);
    write(temp_fd, permissions, strlen(permissions));
    write(temp_fd, "\n", 1);
  }
    

  fclose(daemon_file);

  // deletes the original (old) daemon_conf
  retval=unlink(DAEMON_CONF);
  if (retval == -1) {
    perror("      Error while unlinking daemon_conf (update error) ");
    return -1;
  }

  // recreates daemon_conf in order to write the updated rules in it
  if ((daemon_file = fopen(DAEMON_CONF, "w+")) == NULL) {
    printf("      OOPS. Could not create the new daemon_conf (update error)\n");
    return -1;
  }

  // reposition the stream to the beginning of the temporary file
  retval = fseek(temp_file, 0, SEEK_SET);
  if (retval == -1) {
    printf("      OOPS. Could not reposition stream (update error)\n");
    return -1;
  }

  
  // writes the new daemon_conf using the data written on the temporary file
  while (1) {
    fgets (line, 400, temp_file);
    if (feof (temp_file))
      break;
    line[strlen(line)-1]='\0';
    fwrite(line, sizeof(char), strlen(line), daemon_file);
    fwrite("\n", sizeof(char), 1, daemon_file);
  }
 
  // closes all file descriptors
  close(temp_fd);
  fclose(temp_file);
  fclose(daemon_file);

  // deletes the temporary file
  retval=unlink(temp_file_path);
  if (retval == -1) {
    perror("      Error while unlinking the temporary file (update error) ");
    return -1;
  }

  return 0;

}
//--------------------------------------------------------------------------------





//--------------------------------------------------------------------------------
// this function analyses the answer produced by the frontend in response
// to some query we have forwarded

int analyse_frontend_answer(char query_type, int frontend_answer, 
			    char *md5hash, char *app_path)
{

  struct hashtable_record *ht_record;
  int retval;
 
    
  switch (frontend_answer) {
  
  case NO_ERROR_IN_FRONTEND:
    printf("      An error occurred in the frontend\n");
    return NO_ERROR_IN_FRONTEND;

  case YES_SAVE_IN_FILE:

    // updates the daemon_conf
    retval = update_file(query_type, YES, app_path, md5hash);
    if (retval == -1)
      return NO_ERROR_IN_DAEMON;
    
    printf("      The config file has been updated!\n");    

    // if no error occured, continue and execute 'case YES' in order to
    // update the hashtable too

  case YES:

    printf("    Got answer. User said YES\n");
    // must allocate new area because only the pointer to the hashtable record is kept
    ht_record = (struct hashtable_record *) malloc(sizeof(struct hashtable_record));

    strcpy(ht_record -> md5hash, md5hash);
    if (query_type == TG_PERMIT_SERVER) {
      SET_PERMIT_SERVER(ht_record -> opts);
      SET_HAS_INFO_PERMIT_SERVER(ht_record -> opts);
    }
    else
      if (query_type == TG_ASK_PERMIT_APP) {
	SET_PERMIT_APP(ht_record -> opts);
	SET_HAS_INFO_PERMIT_APP(ht_record -> opts);
      }


    if (insert_in_hash(app_path, ht_record)==-1) {
      printf("      The answer could not be stored in the hashtable!\n");
      free(ht_record);
      return NO_ERROR_IN_DAEMON;
    }
    else
      printf("        Answer has been stored in hashtable (%d).\n", ht_record->opts);
    return YES;
    

  case NO_SAVE_IN_FILE:

    // updates the daemon_conf
    retval = update_file(query_type, NO_SAVE_IN_FILE, app_path, md5hash);
    if (retval == -1)
      return NO_ERROR_IN_DAEMON;
    
    printf("      The config file has been updated!\n");    

    // if no error occured, continue and execute 'case NO_USER_FORBID' in order to
    // update the hashtable too


  case NO_USER_FORBID:

    // must allocate new area because only the pointer to the hashtable record is kept
    ht_record = (struct hashtable_record *) malloc(sizeof(struct hashtable_record));

    printf("    Got answer. User said NO\n");
    strcpy(ht_record -> md5hash, md5hash);
    if (query_type == TG_PERMIT_SERVER) {
      SET_DENY_SERVER(ht_record -> opts);
      SET_HAS_INFO_PERMIT_SERVER(ht_record -> opts);
    }
    else
      if (query_type == TG_ASK_PERMIT_APP) {
	SET_DENY_APP(ht_record -> opts);
	SET_HAS_INFO_PERMIT_APP(ht_record -> opts);
      }

    if (insert_in_hash(app_path, ht_record)==-1) {
      printf("      The answer could not be stored in the hashtable!\n");
      free(ht_record);
      return NO_ERROR_IN_DAEMON;
    }
    else {
      printf("      Answer has been stored in hashtable (%d).\n", ht_record->opts);
      return NO_USER_FORBID;
    }


  default:
    printf("      Received an unknown answer from the frontend (%d)!\n", frontend_answer);
    return NO_ERROR_IN_FRONTEND;
    
  }
}    



//--------------------------------------------------------------------------------
// if the daemon does not have any information to take a decision, this function
// forwards the query to the frontend and analyses the user answer

int try_ask_the_user(struct tg_query module_query, char *hash, char *file_path) 
{
  int retval;

  // the hash table doesnt have enough info, but we can still ask the user
  retval =  forward_query_to_frontend(module_query);

  // -1 means that the frontend could not be contacted
  if (retval == -1) {
    printf("    The frontend is not available.\n");
    return -1;
  }
  else {
    printf("    Forwarding query to frontend.. done!\n");

    // analyse the frontend answer based of the query type received from the module
    return analyse_frontend_answer(module_query.query_type, retval, hash, file_path);
	
  }
}
//--------------------------------------------------------------------------------





//--------------------------------------------------------------------------------
// decides what to do (DENY, ask the user, ..) based on the app's permissions
// that have been found on the hashtable

int check_app_permissions(struct tg_query module_query, int app_permissions, 
			  char *hash, char *file_path)
{

  int user_answer;

  switch(module_query.query_type) {

  case TG_PERMIT_SERVER:

    if (ISSET_HAS_INFO_PERMIT_SERVER(app_permissions))
      if (ISSET_PERMIT_SERVER(app_permissions)) {
	printf("    Daemon configured to PERMIT this SERVER\n");
	return YES;
      }
      else {
	printf("    Daemon configured to DENY this SERVER\n");
	return NO_ACCESS_IS_DENIED;
    }
    else {

      printf("    Daemon does not know if PERMIT_SERVER is ok...\n");
      // daemon does not have info, so let's ask the user
      user_answer = try_ask_the_user(module_query, hash, file_path);
      
      // if the frontend could not be contacted we are obligated to deny the access
      if (user_answer == -1) 
	user_answer = NO_NOT_IN_HASHTABLE;

      return user_answer;
    }


  case TG_ASK_PERMIT_APP:


    if (ISSET_HAS_INFO_PERMIT_APP(app_permissions))
      if (ISSET_PERMIT_APP(app_permissions)) {
	printf("    Daemon configured to PERMIT this APP\n");
	return YES;
      }
      else {
	printf("    Daemon configured to DENY this APP\n");
	return NO_ACCESS_IS_DENIED;
    }
    else {

      printf("    Daemon does not know if PERMIT_APP is ok...\n");
      // daemon does not have info, so let's ask the user
      user_answer = try_ask_the_user(module_query, hash, file_path);
      
      // if the frontend could not be contacted we are obligated to deny the access
      if (user_answer == -1)
	user_answer = NO_NOT_IN_HASHTABLE;

      return user_answer;
    }



  default:

    printf("         Received an unknown query from the module (%d)!\n", module_query.query_type);
    return NO_ERROR_IN_FRONTEND;
  }
}
//--------------------------------------------------------------------------------






//--------------------------------------------------------------------------------
// this is the generic function that will be called in order to
// process a query received from the module

void *process_module_query(void *data) 
{

  struct tg_query answer;
  struct tg_query module_query = ((struct data_to_process *)data) -> query;
  char hash[MD5HASH_SIZE] = "";
  char file_path[MAX_LINE_LENGTH];
  int i, retval;

  /* printf("sender: %d   seqno: %d    query_type: %d    query_data:  %d", (int)module_query.sender,
 	 module_query.seqno, (int)module_query.query_type, module_query.query_data); */

  answer.seqno      = module_query.seqno;
  answer.sender     = TG_DAEMON;
  answer.query_type = TG_RESPOND_PERMIT_APP;

  if ( calc_md5(module_query.query_data, hash, file_path) == -1) {
    printf("       Could not calculate the md5hash!\n");
    answer.query_data = NO_ERROR_IN_DAEMON;
  }
  else {


    printf("    Query from module wants to know if\n");
    if (module_query.query_type == TG_ASK_PERMIT_APP)
      printf("       PERMIT_APP %s\n", file_path);
    else {
      if (module_query.query_type == TG_PERMIT_SERVER)
	printf("       PERMIT_SERVER %s\n", file_path);
      else
	printf("       -- oops. Invalid query type: %d\n       (app: %s)\n",
	       module_query.query_type, file_path);
    }
    
    printf("        with hash %s\n", hash);
    
    retval = verify_app_in_hash(file_path, hash);



    switch (retval) {

    case -NO_WRONG_HASH:
      printf("    Incorrect hash! Verify the integrity of the application!\n");
      answer.query_data = NO_WRONG_HASH;
      break;

    case -NO_NOT_IN_HASHTABLE:

      printf("    Daemon does not know anything about this application.\n");

      answer.query_data = try_ask_the_user(module_query, hash, file_path);
      
      // if the frontend could not be contacted we are obligated to deny the access
      if (answer.query_data == -1) 
	answer.query_data = NO_NOT_IN_HASHTABLE;

      break;


    default:   // verify_app_in_hash returned the app's permissions

      printf("    Checking the permissions for the application..\n");

      // this function will forward the query to the frontend if necessary
      answer.query_data = check_app_permissions(module_query, retval, hash, file_path);

      // if the frontend could not be contacted we are obligated to deny the access
      if (answer.query_data == -1)
	answer.query_data = NO_ACCESS_IS_DENIED;
      break;
    }
  }

  printf("    Sending ");
  if (answer.query_data == YES)
    printf("YES to the module.. ");
  else
    printf("NO to the module.. ");
  

  retval=write(((struct data_to_process *)data) -> sock, &answer, sizeof(struct tg_query));
  
  free(data);
  close (((struct data_to_process *)data) -> sock);
  pthread_exit(0);  
}
//--------------------------------------------------------------------------------




//--------------------------------------------------------------------------------
// this is the generic function that will be called in order to
// print the query received by the module; the access is always
// permited, since this function is only used to provide information
// about the applications trying to use the network in order to 
// generate the first version of the config file (daemon.conf)

void *store_query(void *data) 
{

  struct tg_query answer;
  struct tg_query module_query = ((struct data_to_process *)data) -> query;
  char hash[MD5HASH_SIZE] = "";
  char file_path[MAX_LINE_LENGTH];

  int i, retval;
  struct hashtable_record *ht_record;


  answer.seqno      = module_query.seqno;
  answer.sender     = TG_DAEMON;
  answer.query_type = TG_RESPOND_PERMIT_APP;

  if ( calc_md5(module_query.query_data, hash, file_path) == -1) {
    printf("       Could not calculate the md5hash!\n");
    answer.query_data = NO_ERROR_IN_DAEMON;
  }
  else {

    // must allocate new area because only the pointer to the hashtable record is kept
    ht_record = (struct hashtable_record *) malloc(sizeof(struct hashtable_record));

    strcpy(ht_record -> md5hash, hash);

    if (module_query.query_type == TG_ASK_PERMIT_APP) {
      SET_PERMIT_APP(ht_record -> opts);
      SET_HAS_INFO_PERMIT_APP(ht_record -> opts);
    }
    else {
      if (module_query.query_type == TG_PERMIT_SERVER) {
	SET_PERMIT_SERVER(ht_record->opts);
	SET_HAS_INFO_PERMIT_SERVER(ht_record->opts);
      }
      else
	printf("       -- oops. Invalid query type: %d\n", module_query.query_type);
    }


    if (insert_in_hash(file_path, ht_record)==-1) {
      printf("      The answer could not be stored in the hashtable!\n");
      free(ht_record);
      return;
    }
/*     else */
/*       printf("        Answer has been stored in hashtable (%d).\n", ht_record->opts); */

  }

  // always allows the access
  answer.query_data = YES;
  retval=write(((struct data_to_process *)data) -> sock, &answer, sizeof(struct tg_query));
  
  free(data);
  close (((struct data_to_process *)data) -> sock);
  
}
//--------------------------------------------------------------------------------











//--------------------------------------------------------------------------------
int forward_query_to_frontend(struct tg_query query)
{

  int retval;
  int sockfd;

  struct sockaddr_un address;
  struct tg_query answer;

  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

  /*  Name the socket, as agreed with the server.  */
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, PATH_FRONTEND);

  /*  Now connect our socket to the server's socket.  */
  retval = connect(sockfd, (struct sockaddr *)&address, sizeof(address));


  if(retval == -1) {
    return -1;
  }

  // forwards the module query to the frontend
  query.sender = TG_DAEMON;


  retval = send(sockfd, &query, sizeof(struct tg_query), 0);

  // make the socket non blocking
  fcntl(sockfd,F_SETFL,O_NONBLOCK);
  // and reads the answer
  retval = -1;
  while (retval == -1)
    retval =  recv(sockfd, &answer, sizeof(answer), 0);

  close(sockfd);
  return answer.query_data;
}
//--------------------------------------------------------------------------------








//--------------------------------------------------------------------------------

int calc_md5(pid_t pid, char *hash, char *real_path)
{

    FILE *file;
    int err, i;

    char tmphash[MD5HASH_SIZE], tmp[10];
    char link_path[MAX_LINE_LENGTH]="/proc/";

    sprintf(tmp, "%d", pid);
    strcat(link_path, tmp);
    strcat(link_path, "/exe");


    if ((err=readlink(link_path, real_path, MAX_LINE_LENGTH)) == -1) {
	perror("      OOPS. Error when trying to readlink() /proc: ");

	// debugging info is commented (calling system is dangerous!)
	/* 	strcpy(link_path, "readlink /proc/"); */
	/* 	sprintf(tmp, "%d", pid); */
	/* 	strcat(link_path, tmp); */
	/* 	strcat(link_path, "/exe"); */
	/* 	system(link_path); */
	return -1;
    }
    // readlink does not append a NUL  character
    real_path[err]='\0';

    if ((file = fopen(real_path, "r")) == NULL) {
	perror("      OOPS. Error when trying to fopen() /proc file: ");
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
//--------------------------------------------------------------------------------







//--------------------------------------------------------------------------------
int insert_in_hash(char *path, struct hashtable_record *ht_record)
{

  int retval;
  struct hashtable_record *data;
  
  pthread_mutex_lock( &mutex );
  data = pblHtLookup(ht, path, strlen(path));

  // record already exists, so we delete it and reinsert with the new info
  if (data) {

    // copies the existing opts to the ht_record being inserted
    if (ISSET_HAS_INFO_PERMIT_APP(data->opts)) {
      SET_HAS_INFO_PERMIT_APP(ht_record->opts);
      if (ISSET_PERMIT_APP(data->opts))
	SET_PERMIT_APP(ht_record->opts);
      else
	SET_DENY_APP(ht_record->opts);
    }
    if (ISSET_HAS_INFO_PERMIT_SERVER(data->opts)) {
      SET_HAS_INFO_PERMIT_SERVER(ht_record->opts);
      if (ISSET_PERMIT_SERVER(data->opts))
	SET_PERMIT_SERVER(ht_record->opts);
      else
	SET_DENY_SERVER(ht_record->opts);
    }
      
    retval = remove_from_hash(path, data->md5hash);
    if (retval == -1) {
      printf("      OOPS. Error while updating %s in the hashtable!\n", path);
      printf("      md5=%s opts=%d\n", data->md5hash, data->opts);
      return -1;
    }
  }
   
  retval = pblHtInsert( ht, path, strlen(path), ht_record);
  if (retval != 0)
    if (retval == -1) {
      printf("      OOPS. Error while adding/updating %s to the hashtable!\n", path);
      printf("      md5=%s opts=%d\n", ht_record->md5hash, ht_record->opts);
      return -1;
    }
	
  pthread_mutex_unlock( &mutex );	
	
  return 0;

}
//--------------------------------------------------------------------------------








//--------------------------------------------------------------------------------
int parse_app_opts(char *app_opts, int verbose_mode)
{
  char *tok, *comment;
  const char *delim = " \t";
  int found_comment = 0;
  int opts = 0;

  // initially we don't have any informations about the app
  UNSET_HAS_INFO_PERMIT_APP(opts);
  UNSET_HAS_INFO_PERMIT_SERVER(opts);


  tok = strsep(&app_opts, delim); 
  while( tok ) {

    if (tok[0] != '\0') {            // still reading tokens?

      if (comment=index(tok, '#')) {   // is there a comment inside the token?
	comment[0]='\0';               // ignore everything up to the '#'

	if (tok[0] != '\0')            // if the token is not empty, we parse..
	  found_comment=1;
	else
	  break;                       // otherwise we leave
      }

      if (!(strcmp(tok, PERMIT_APP))) {
	if (verbose_mode)
	  printf("PERMIT_APP "); 
	SET_PERMIT_APP(opts);
	SET_HAS_INFO_PERMIT_APP(opts);
      }
      else
	if (!(strcmp(tok, PERMIT_SERVER))) {
	  if (verbose_mode)
	    printf("PERMIT_SERVER "); 
	  SET_PERMIT_SERVER(opts);
	  SET_HAS_INFO_PERMIT_SERVER(opts);
	}
	else
	  if (!(strcmp(tok, DENY_SERVER))) {
	    if (verbose_mode)
	      printf("DENY_SERVER "); 
	    SET_DENY_SERVER(opts);
	    SET_HAS_INFO_PERMIT_SERVER(opts);
	  }
	  else
	    if (!(strcmp(tok, DENY_APP))) {
	      if (verbose_mode)
		printf("DENY_APP ");
	      SET_DENY_APP(opts);
	      SET_HAS_INFO_PERMIT_APP(opts);
	    }
	    else
	      printf("(err parsing file: %s) ", tok);

      if (found_comment)
	break;
    }
    tok = strsep( &app_opts, delim); 
  }

  return opts;

}
//--------------------------------------------------------------------------------








//--------------------------------------------------------------------------------
int init_hash(int silent)
{

  int retval, i;
  int hash_size=0;
  FILE *file;
  char app_name[MAX_LINE_LENGTH];
  char app_opts[MAX_LINE_LENGTH];
  struct hashtable_record *ht_record;

  ht = pblHtCreate();
  if (ht == NULL) {
    printf("      OOPS. Could not create the hashtable!\n");
    return -1;
  }


  if ((file = fopen(DAEMON_CONF, "r")) == NULL) {
    printf("      OOPS. Could not open %s!\n", DAEMON_CONF);
    return -1;
  }


  while (1) {

    // must allocate new area because only the pointer to the hashtable record is kept
    ht_record = (struct hashtable_record *) malloc(sizeof(struct hashtable_record));

    fgets (app_name, MAX_LINE_LENGTH, file);
    if (feof (file)) {
      free(ht_record);
      break;
    }

    app_name[strlen(app_name)-1] = '\0';


    fgets (ht_record -> md5hash, MD5HASH_SIZE, file);
    if (feof (file)) {
      printf("      Bad configuration file (premature ending at %s)\n", app_name);
      free(ht_record);
      return -1;
    }
    ht_record -> md5hash[strlen(ht_record -> md5hash)-1] = '\0';


    fgets (app_opts, MAX_LINE_LENGTH, file);
    if (feof (file)) {
      printf("      Bad configuration file (premature ending at %s)\n", app_name);
      free(ht_record);
      return -1;
    }
    app_opts[strlen(app_opts)-1] = '\0';

    if (!silent)
      printf("Adding [%s -> %s] to the hashtable\n          ", app_name, ht_record -> md5hash);
    ht_record -> opts = parse_app_opts(app_opts, !silent);
    if (!silent)
      printf("(%d)\n", ht_record -> opts);
      
    
    if (insert_in_hash(app_name, ht_record) != 0) {
      printf("      Error while adding [%s -> %s] to the hashtable\n", app_name, ht_record -> md5hash);
      free(ht_record);
      return -1;
    }

    hash_size++;
  }

  if (!silent)
    printf("\nRead %d rules from the configuration file!\n", hash_size);

  
/*   for (i=0; i<5; i++) { */
/*     ht_record = pblHtLookup( ht, data_x[i][0], strlen(data_x[i][0])); */
/*     fprintf( stdout, "pblHtLookup( ht, %s %d ) md5 = %s, opts = %d\n", */
/* 	     data_x[i][0], strlen(data_x[i][0]), ht_record ? ht_record->md5hash : "NULL", */
/* 	     ht_record ? ht_record -> opts : -1); */
/*   } */

  
  fclose(file);
  return 0;
}
//--------------------------------------------------------------------------------







//--------------------------------------------------------------------------------
int verify_app_in_hash(char *path, char *md5hash)
{

  struct hashtable_record *ht_record;

  ht_record = pblHtLookup( ht, path, strlen(path));
  if (ht_record) {
    if (!(strcmp(ht_record -> md5hash, md5hash))) {
      return ht_record -> opts;  // the md5hash is ok, so return the permissions (DENY_APP, etc)
    }
    else {
      return -NO_WRONG_HASH;  // wrong md5hash!
    }
  }
  else {
    return -NO_NOT_IN_HASHTABLE;   // daemon does not know this app..
  }

}
//--------------------------------------------------------------------------------







//--------------------------------------------------------------------------------
int remove_from_hash(char *path, char *md5hash)
{

  char *data;
  int retval;
	
  pthread_mutex_lock( &mutex );
  
  retval = pblHtRemove( ht, path, strlen(path));
  if (retval != 0)
    if (retval == -1) {
      printf("      OOPS. Error removing (%s) from the hashtable!\n", path);
      return -1;
    }
  // else == record does not exist.. ignore
  
  pthread_mutex_unlock( &mutex );
  
  return 0;
}
//--------------------------------------------------------------------------------






//--------------------------------------------------------------------------------
int delete_hash_table()
{

  struct hashtable_record *data;
  char *x;
  int retval;

  // removes all items from a hash table
  for(data = (struct hashtable_record *)pblHtFirst( ht ); data; data = pblHtNext( ht )) {
    free(data);
    pblHtRemove( ht, 0, 0 );
  }

  retval = pblHtDelete( ht );
  if (retval != 0) {
    printf("      OOPS. Error %d while deleting the hashtable (%d) !\n", retval, pbl_errno);
    printf(" errno nao tah vazia = %d\n", PBL_ERROR_EXISTS);
    return -1;
  }

  return 0;
}
//--------------------------------------------------------------------------------


// called when someone types Ctrl-C
void terminate(int i) {
  
  struct hashtable_record *ht_record;
  char *s="/bin/ping";
  char *tmp;
  

  // if the daemon is running in 'generate_first_config_file', we
  // print everything that has been stored in the hashtable 
  if (generate_first_config_file)
    for( ht_record = pblHtFirst( ht ); ht_record; ht_record = pblHtNext( ht )) {
      tmp=(char *)pblHtCurrentKey(ht);
      printf("%s\n%s\n", tmp, ht_record->md5hash);
      
      if (ISSET_HAS_INFO_PERMIT_APP(ht_record->opts))
	if (ISSET_PERMIT_APP(ht_record->opts)) {
	  printf("PERMIT_APP ");
	}
	else {
	  printf("DENY_APP ");
	}

      if (ISSET_HAS_INFO_PERMIT_SERVER(ht_record->opts))
	if (ISSET_PERMIT_SERVER(ht_record->opts)) {
	  printf("PERMIT_SERVER ");
	}
	else {
	  printf("DENY_SERVER ");
	}

      printf("\n");

      free(tmp);
    }


  if (!generate_first_config_file)
    printf("\n\n\nFreeing hashtable..");

  if (delete_hash_table()) {
    printf("Error! Could not free the hashtable!\n");
    exit(-1);
  }

  if (!generate_first_config_file)
    printf("\nbye.\n\n");

  exit(0);
}




//--------------------------------------------------------------------------------




int main(int argc, char *argv[])
{

  int my_address_len, client_address_len;

  struct sockaddr_un my_address;
  struct sockaddr_un client_address;

  time_t rawtime;

  int listener;     // listening socket descriptor
  int new_sockfd;

  int newfd;        // newly accept()ed socket descriptor

  int retval;
  int yes=1;        // for setsockopt() SO_REUSEADDR, below
  int i, j;

  char *data;

  struct tg_query tg_q;


  // makes the daemon run in background automatically
  int pid = fork();
  if (pid == -1) {
    perror("Fork error...\n");
    exit(1);
  }
  if (pid != 0) {
    exit(0); // this is the parent, hence should exit
  }
											



  if (argc > 1)
    for (i=1; i< argc; i++)
      if (strcmp(argv[i], "--generate-config")==0)
	generate_first_config_file=1;
      else
	generate_first_config_file=0;


  if (init_hash(generate_first_config_file))
    return -1;


  /*  Remove any old socket and create an unnamed socket for the server.  */
  unlink(PATH_MODULE);
  listener = socket(AF_UNIX, SOCK_STREAM, 0);

  // lose the pesky "address already in use" error message
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes,
		 sizeof(int)) == -1) {
    perror("    Could not setsockopt!\n");
    exit(1);
  }

  /*  Name the socket.  */
  my_address.sun_family = AF_UNIX;
  strcpy(my_address.sun_path, PATH_MODULE);
  my_address_len = sizeof(my_address);


  retval = bind(listener, (struct sockaddr *)&my_address, my_address_len);
  if (retval == -1) {
    perror("    Could not bind to the socket!\n");
    exit(1);
  }

  retval = chmod(PATH_MODULE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  if (retval == -1) {
    perror("    Could not change the socket permissions!\n");
    exit(1);
  }


  if (listen(listener, 2048) == -1) {
    perror("    Could not listen!\n");
    exit(1);
  }

  if (!generate_first_config_file)
    printf("\n\nWaiting for module queries..\n", errno, strerror(errno));

  signal(SIGINT, terminate);
  signal(SIGTERM, terminate);

  
  // main loop
  for(;;) {

    client_address_len = sizeof(client_address);
    if((new_sockfd = accept(listener,
			    (struct sockaddr *)&client_address,
			    &client_address_len)) == -1) {
      perror("    Oops. Accept error!\n");
    }
    else {
      if (!generate_first_config_file) {
	time ( &rawtime );
	printf("\n\n%s", ctime(&rawtime));
      }

      retval = read(new_sockfd, &tg_q, sizeof(struct tg_query));

      struct data_to_process *data_and_socket;
      data_and_socket = (struct data_to_process *) malloc(sizeof(struct data_to_process));
      data_and_socket->query = tg_q;
      data_and_socket->sock  = new_sockfd;

      pthread_t new_thread;

      if (!generate_first_config_file) {
	pthread_create(&new_thread, NULL, &process_module_query, data_and_socket);
	pthread_detach(new_thread);
      }
      else {
	pthread_create(&new_thread, NULL, &store_query, data_and_socket);
	pthread_detach(new_thread);
      }
    }
  }

}
