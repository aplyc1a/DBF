#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import paramiko
import socket
import hashlib
from ftplib import FTP

def ssh_connector(host,port,user,password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, user, password)
        print "{successful:%s}" %password
        
    except Exception, e:
        print "{failure:(%s)%s}" % (socket.gethostbyname(socket.gethostname()), str(e)) 
    finally:
        ssh.close()

def ftp_connector(host,port,user,password):
    try:
        ftp = FTP()
        # ftp.set_debuglevel(2)
        ftp.connect(host, port)
        ftp.login(user, password)
        print "{successful:%s}" %password
    except Exception, e:
        print "{failure:(%s)%s}" % (socket.gethostbyname(socket.gethostname()), str(e)) 
    finally:
        ftp.close()
def telnet_connector(host,port,user,password):
    pass

def custom_connector(host,port,user,password):
    pass

def connect_target(target_link, user, passwd):
    srv_list=['ssh','ftp']
    srv = target_link.split(':',2)[0]
    host = target_link.split(':',2)[1][2:]
    port = target_link.split(':',2)[2]
    
    if srv in srv_list:
        eval(srv+"_connector")(host, port, user, passwd)
    else:
        print "{failure:(%s)%s}" % (socket.gethostbyname(socket.gethostname()), "protocol name illegal.") 

def main():
    parser = optparse.OptionParser('usage % prog -T <target_link> -u <user> -P <password>')
    parser.add_option('-T', dest = 'target_link', type = 'string', \
                      help = 'Provide target information. Format: ssh://10.1.1.1:22')
    parser.add_option('-u', dest = 'user', type = 'string', help = 'specify user')
    parser.add_option('-p', dest = 'passwd', type = 'string', help = 'specify password')

    (options,args)= parser.parse_args()
    target_link=options.target_link
    user=options.user
    passwd=options.passwd

    if target_link == None or user == None or passwd == None :
        print "{%s/?user=%s&passwd=%s}" %(target_link,user,passwd)
        #print parser.usage
        exit(0)
        
    connect_target(target_link, user, passwd)

if __name__ == '__main__':
    main()
    
    
    
