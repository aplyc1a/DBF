# DBF         
Simple Distributed BruteForcer for SSH        
                  
## Requirement         
**OS system** : Debian/RHEL         
**Runtime Environment** : python27 with(paramiko)        
## Introduction        
\>  *owner.py*  : the master control program, which is used to connect zombie_host (read from zombie_file) and create distribute tasks(use password dictionary). owner.py is a simple distributed bruteforcer framework.                       
\>  *zombie.py* : the child script program. After connection between zombie_host and C&C_Server is establish, zombie.py will be automatically downloaded. zombie.py is a bruteforcer agent, but only support SSH cracking this version.               
## Usage                      
\#slow mode                  
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -T ssh -t 30 -d 10                    
\#fast mode             
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -T ssh -t 30 -d 0.2                 
```text                
-H <target host>  : Host IP of target.                 
-p <target_port>  : Port to connect to on the target.                      
-u <target_user>  ：Provide username when connect to the target.                   
-F <passwd_file>  : Dictionary of passwords.                        
-Z <zombie_file>  : Provide zombie's resource. Format: 192.168.0.1:root:toor.              
-T <type>         : Only support SSH service.              
-l <threads>      ：Run threads number of connects in parallel, default 5.               
-c <interval>     : Defines the minimum wait time in seconds, default 5s. DBF use random time interval technology.The actual time interval is 5.0~10.0 seconds.                
        
```
