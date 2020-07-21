#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import paramiko
import socket
import hashlib

def connect_target(host, user, port, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, user, password)
        print "{%s:%s}" %(hashlib.md5("Found SSH Password").hexdigest(),password)
        
    except Exception, e:
        print str(e)
        print "Ooops!" + socket.gethostbyname(socket.gethostname()) 
    finally:
        ssh.close()

def main():
    parser = optparse.OptionParser('usage % prog -h <target host> '+\
        '-u <user> -p <port> -P <password>')
    parser.add_option('-H', dest = 'target_host', type = 'string',\
        help = 'specify target host')
    parser.add_option('-u', dest = 'user', type = 'string', help = 'specify user')
    parser.add_option('-p', dest = 'port', type = 'string', \
        help = 'specify service port')
    parser.add_option('-P', dest = 'passwd', type = 'string', \
        help = 'specify password')

    (options,args)= parser.parse_args()
    host=options.target_host
    user=options.user
    passwd=options.passwd
    port=options.port

    if host == None or user == None or passwd == None or port == None:
        print host + user + passwd + port
        print parser.usage
        exit(0)
        
    connect_target(host, user, port, passwd)

if __name__ == '__main__':
    main()