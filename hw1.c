#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAXBUF 4096
#define MAXSERVS 50

#define DEBUG
#define LOG_LEVEL 0

#if defined DEBUG && defined LOG_LEVEL
#define debug(level, ...) do{if(level <= LOG_LEVEL)fprintf(stderr, __VA_ARGS__);}while(0)
#else
#define debug(level, ...) // no-op
#endif

/* Format specifiers for SMTP handshake */
char *helo = "HELO %s\r\n";
char *mail = "MAIL FROM: <%s>\r\n";
char *rcpt = "RCPT TO: <%s>\r\n";
char *data = "%s\r\n";


/* This function returns the email servers
   from a domain in order of priority.
*/
static char** get_servers(char *hostname){
  char buffer[MAXBUF];
  /* MX records for hostname, sorted by priority */
  char *command = "dig mx %s +short | sort -n";
  int n;
  if((n =snprintf(buffer, MAXBUF, command, hostname)) < 0 || n >= MAXBUF){
    debug(3, "Error encoding hostname\n");
    return NULL;
  }
  FILE *records;
  if((records = popen(buffer, "r")) == NULL){
    debug(3, "Error opening records file: %s\n", strerror(errno));
    return NULL;
  }
  char **servers = (char**)malloc(sizeof(char*)*MAXSERVS);
  debug(2, "\nMX records:\n");
  int i;
  for(i = 0; i < MAXSERVS; i++){
    if(fgets(buffer, MAXBUF, records) == 0){
      break;
    }
    /* Parse priority from buffer */
    char *delim;
    if((delim = strpbrk(buffer, " \t"))){
      *delim = 0;
      debug(2, "priority: %s", buffer);
      /* Parse server name from buffer */
      char *server = delim + 1;
      while(server && isspace(*server)){
        server++;
      }
      if(server){
        server[strcspn(server, "\r\n")] = 0;
        debug(2, ", server: %s\n", server);
        servers[i] = (char*)malloc(strlen(server)+1);
        strcpy(servers[i], server);
      }
    } 
  }
  servers[i] = 0;
  if(pclose(records) < 0){
    debug(3, "Error closing records file: %s\n", strerror(errno));
  }
  return servers;
}


/* This function frees the server strings. */
static void free_servers(char **servers){
  if(servers == NULL){ return; }
  int i;
  for(i = 0; i < MAXSERVS && servers[i] != 0; i++){
    free(servers[i]);
  }
  free(servers);
}


/* This function writes to a file descriptor
   using the SMTP format.
*/
static int smtp_send(int fd, char *format, char *message){
  char buffer[MAXBUF];
  int n;
  if((n = snprintf(buffer, MAXBUF, format, message)) < 0 || n >= MAXBUF){
    debug(3, "Error encoding hostname\n");  
    return 0;
  }
  if(write(fd, buffer, strlen(buffer)) < 0){
    debug(3, "Error sending to server: %s\n", strerror(errno));
    return 0;
  }
  buffer[strcspn(buffer, "\r\n")] = 0;
  debug(1, "C: %s\n", buffer);
  return 1;
}


/* This function reads from a file descriptor
   and checks for the correct SMTP response code.
*/
static int smtp_receive(int fd, char *expected_code){
  char buffer[MAXBUF];
  if(read(fd, buffer, MAXBUF) < 0){
    debug(3, "Error reading from server: %s\n", strerror(errno));
    return 0;
  }
  buffer[strcspn(buffer, "\r\n")] = 0;
  debug(1, "S: %s\n", buffer);
  char *code;
  if((code = strtok(buffer, " ")) == NULL || strcmp(code, expected_code) != 0){
    debug(3, "Invalid response code, expected 220\n");
    return 0;
  }
  return 1;
}


/* This function sends an email to an email server. 
*/
static int send_email_to_server(FILE *email, char *server, char *sender, char *receiver){
  /* Parse the sender domain */
  char *domain;
  if((domain = strchr(sender, '@')) == NULL){
    debug(3, "Invalid email format: %s\n", sender);
    return 0;
  }
  domain++;
  /* Connect to email server */
  struct addrinfo *addr;
  char buffer[MAXBUF];
  int rc;
  if((rc = getaddrinfo(server, "25", NULL, &addr)) != 0){
    debug(3, "Error resolving hostname: %s\n", gai_strerror(rc));
    return 0;
  }
  int fd;
  if((fd = socket(addr->ai_family, SOCK_STREAM, 0)) < 0){
    debug(3, "Error creating socket: %s\n", strerror(errno));
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  if(connect(fd, addr->ai_addr, (int)addr->ai_addrlen) < 0){
    debug(3, "Error connecting to server: %s\n", strerror(errno));
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 220 - Service ready */
  if(!smtp_receive(fd, "220")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* HELO - Identity host to email server */
  if(!smtp_send(fd, helo, domain)){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 250 - Requested action okay */
  if(!smtp_receive(fd, "250")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* MAIL - Initiate mail transaction */
  if(!smtp_send(fd, mail, sender)){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 250 */
  if(!smtp_receive(fd, "250")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* RCPT - Identity recipient of email */
  if(!smtp_send(fd, rcpt, receiver)){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 250 */
  if(!smtp_receive(fd, "250")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* DATA - Following lines will be mail data */
  if(!smtp_send(fd, data, "DATA")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  } 
  /* 354 - Start mail input */
  if(!smtp_receive(fd, "354")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* Read data from file */
  while(fgets(buffer, MAXBUF, email)){
    buffer[strcspn(buffer, "\r\n")] = 0;
    if(!smtp_send(fd, data, buffer)){
      close(fd); 
      freeaddrinfo(addr);
      return 0;
    }
  }
  /* Send end of data line: .CRLF */
  if(!smtp_send(fd, data, ".")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 250 */
  if(!smtp_receive(fd, "250")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* QUIT - Receiver must send OK and end transmission */
  if(!smtp_send(fd, data, "QUIT")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  /* 221 - Service closing transmission channel */
  if(!smtp_receive(fd, "221")){
    close(fd); 
    freeaddrinfo(addr);
    return 0;
  }
  close(fd); 
  freeaddrinfo(addr);
  return 1;
}

/* This function sends an email, using the
   email to determine sender and recipient.
*/
int send_email(char *filename){ 
  FILE *email;
  if((email = fopen(filename, "r")) == NULL){
    debug(3, "Error opening file: %s\n", strerror(errno));
    return 0;
  }
  char buffer[MAXBUF];
  char *sender = NULL, *receiver = NULL;
  /* Parse sender and receiver from file*/
  while(fgets(buffer, MAXBUF, email)){
    char *delim;
    /* Parse sender from file */
    if(sender == NULL && (delim = strchr(buffer, '<'))){
      *delim = 0;
      char *term;
      if((term = strchr(++delim, '>'))){
        *term = 0;
        sender = (char*)malloc(strlen(delim)+1);
        strcpy(sender, delim);
      }
    }
    /* Parse receiver from file */
    else if(receiver == NULL && (delim = strchr(buffer, '<'))){
      char *term;
      if((term = strchr(++delim, '>'))){
        *term = 0;
        receiver = (char*)malloc(strlen(delim)+1);
        strcpy(receiver, delim);
        break;
      }
    }
  }
  /* Test for missing information */
  if(sender == NULL || receiver == NULL){
    debug(3, "Incorrect file format, missing headers\n");
    free(sender); free(receiver);
    fclose(email);
    return 0;
  }
  /* Parse the domain */
  char *hostname;
  if((hostname = strchr(receiver, '@')) == NULL){
    debug(3, "Incorrect email format: %s\n", receiver);
    free(sender); free(receiver);
    fclose(email);
    return 0;   
  }
  hostname++;
  char **servers;
  if((servers = get_servers(hostname))){
    /* Try to connect to each email server, ordered by priority */
    int i;
    for(i = 0; i < MAXSERVS && servers[i] != 0; i++){
      debug(3, "\nTrying server: %s ..\n", servers[i]);
      /* Reset file position and try contacting email servers */
      rewind(email);
      if(send_email_to_server(email, servers[i], sender, receiver)){  
        free(sender); free(receiver);
        free(email);
        return 1;
      }
    }
  }
  else{
    debug(3, "Error: No MX records found for %s", hostname);
  }
  free(sender); free(receiver);
  free_servers(servers);
  fclose(email);
  return 0;
}

int main(int argc, char *argv[]){
  if(argc < 2){
    debug(0, "Usage: ./hw1 <file #1> <file #2> ...\n");
    exit(-1);
  }   
  int i;
  for(i = 1; i < argc; i++){
    debug(3, "[%d] '%s'\n", i, argv[i]);
    if(send_email(argv[i])){
      debug(0, "'%s' successfully sent!\n", argv[i]);
    }
    else{
      debug(0, "'%s' could not be sent!\n", argv[i]);
    }
  }
  return 0;
}
