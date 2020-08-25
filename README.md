# ants(DBF)         
Simple Distributed BruteForcer        
                  
## Requirement         
**OS system** : Debian/RHEL         
**Runtime Environment** :                   
\>  main-host: python3 with lib(paramiko)               
\>  zombie-host: python3 with lib(paramiko)      
## Introduction        
\>  *owner.py*  : the master control program ,which is used to connect zombie_host (read from zombie_file) and create distribute tasks(use password dictionary). owner.py is a simple distributed bruteforcer framework.                       
\>  *zombie.py* : the child script program, attacker copy zombie.py to zombie_host after connection succeed. zombie.py is a bruteforcer agent, support SSH&FTP cracking this version.               
\#slow mode                    
eg1: Zombie works 1s interval, totally 10 threads        
python owner.py -H 192.168.0.10 -p 22 -u root -F passwd.lst -Z zombie.lst -S ssh -t 10 -d 1         
eg2: Each zombie works 1min interval, totally 300 threads        
python owner.py -T ssh://192.168.0.10:22 -u root -F passwd.lst -Z zombie.lst -t 300 -d 60      
            
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

![usage-1](https://github.com/aplyc1a/ants/blob/develop/usage-1.png)                      
![usage-2](https://github.com/aplyc1a/ants/blob/develop/usage-2.png)                     
![usage-3](https://github.com/aplyc1a/ants/blob/develop/usage-3.png)                                     


\> 鉴于代理端的扫描效率非常低，原因与设计架构有关：            
1.owner与zombie之间每次派发任务都需要建立一次完整的socket的连接；            
2.zombie端使用低效的python进行开发同时对目标的连接基于shell命令；            
3.owner端对zombie的任务派发写的非常粗糙。            
所以我在用C重写zombie部分。目前的zombie支持对redis、ssh、ftp的连接，想要实现一个稳定可用的zombie agent还有很多困难与工作要做。            
1.支持几个更常见的协议:smb、rdp、telnet、以及自定义下发shell命令；            
2.zombie要能以后台运行的方式驻留起来；            
3.支持owner直接派发的目标字典进行口令扫描;            
4.owner端对接问题;            
5.owner端支持唤醒zombie;            
6.上面的几点完成后，才相当于实现了hydra的代理分布式扫描功能。长远的来说，要支持agent端自发现扫描，并将结果能够以某种方式反馈给owner。            
7.agent端支持对zombie端的C2管理。            
            
            
如果您有什么好的想法与建议，请您不吝赐教(aplyc1a@protonmail.com)~            
这只是一个概念性玩具，无意于违法与犯罪行为，只是想写写好玩的东西。                  

