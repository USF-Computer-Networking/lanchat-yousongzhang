for IETF Standards and RFCs assginment move to : [readme2.md](https://github.com/USF-Computer-Networking/lanchat-yousongzhang/blob/master/README2.md)

# LanChat

lanchat is a python tool which scans hosts of same LAN and sends text messages in UDP packets.   
Function:
1.  show list of IP and Mac of hosts in the same LAN 
2.  send message by UDP packet 
3.  recieve message by listen UDP packet 
4.  show help info 

# how to install

sudo -H pip install -r requirements.txt 



# How to run it
  run in sudo mode:   
  sudo python lanchat.py 
  
  input> mode type quit will exit running.  
  
  show help info  
  sudo python lanchat.py -h  
  example:    
sudo python lanchat.py -h   
lanchat scans hosts of same LAN and show hosts list   
lanchat will listen local IP and Port (which is set by user)   
lanchat send message to host when user set remore IP and Port   
lanchat send message begins with: input>     
Listen and Send with default (local) IP and Port(8888), it works.    
input quit to exit lanchat: input>quit    
  
# run test in default
   lanchat.py can run with all Port and IP default.  
  in Default model. program listen local IP with port 8888 for UDP package. also send UDP message to Local IP with port 8888. 
  so this is easy way to test.  
  

  
  example: 
  ![example](http://www.99sns.com/lanchat.png)
  

  
 
  
