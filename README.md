# ants(DBF)         
Simple Distributed BruteForcer        
                  
## Requirement         
**OS system** : Debian/RHEL         
**Runtime Environment** :                   
\>  main-host: python3 with lib(paramiko)               
\>  zombie-host: python3 with lib(paramiko)、libssh-dev(C version)      
## Introduction        
\>  *owner.py*  : the master control program ,which is used to connect zombie_host (read from zombie_file) and create distribute tasks(use password dictionary). owner.py is a simple distributed bruteforcer framework.                       
\>  *zombie.py* : the child script program, attacker copy zombie.py to zombie_host after connection succeed. zombie.py is a bruteforcer agent, support SSH&FTP cracking this version.               
\#slow mode                    
eg1: Zombie works 1s interval, totally 10 threads        
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -S ssh -t 10 -c 1         
eg2: Each zombie works 1min interval, totally 300 threads        
python owner.py -T ssh://192.168.0.10:22 -u root -F passwd.lst -Z zombie.lst -t 300 -c 60      
            
```text                
-H <target host>  : Host IP of target.                 
-p <target_port>  : Port to connect to on the target.                      
-u <target_user>  ：Provide username when connect to the target.                   
-S <type>         : Only support SSH/FTP service now.              
-T <target>       : Provide target information. Format: ssh://10.1.1.1:22    (support ssh/ftp/redis now.)
-Z <zombie_file>  : Provide zombie's resource. Format: 192.168.0.1:root:toor.              
-F <passwd_file>  : Dictionary of passwords.                        
-t <threads>      ：Run threads number of connects in parallel, default 5.               
-c <interval>     : Defines the minimum wait time in seconds, default 5s. The ants(DBF) use random time interval technology. The actual time interval is 5.0~10.0 seconds.                
```                 

![usage-1](https://github.com/aplyc1a/ants/blob/develop/usage-1.png)                      
![usage-2](https://github.com/aplyc1a/ants/blob/develop/usage-2.png)                     
![usage-3](https://github.com/aplyc1a/ants/blob/develop/usage-3.png)                                     


PS：           
\> zombie.py代理端的扫描效率比较低（在秒级响应方面比较吃力），原因与设计架构有关：            
 1.owner与zombie之间每次派发任务都需要建立一次完整的socket的连接；            
 2.zombie端使用低效的python进行开发同时对目标的连接基于shell命令；            
 3.owner端对zombie的任务派发写的非常粗糙。            
         
\> C重写zombie部分。            
 **给自己的规划笔记：**               
 1.协议方面：支持几个更常见的协议如，smb、rdp、telnet、自定义管理命令族；（自定义部分现在只留了个自杀按钮）            
 2.zombie要能以后台运行的方式驻留起来；（已支持）            
 3.减少通信：支持使用owner直接派发的字典进行口令扫描;（目前仍只支持一次一条的派发形式）            
 4.owner端对接问题;（协议返回的消息这块稍微有点乱，抽空统一一下）            
 5.owner端支持唤醒zombie; （自定义管理命令族）          
 6.传染：暂不支持，感觉现在zombie端写的太烂了。（自定义管理命令族）            
 7.管理：暂不支持，等对接做的比较好的时候再做。（自定义管理命令族）              
              
如果您有什么好的想法与有用的建议，万望不吝赐教(@mailto:aplyc1a@protonmail.com)~            

