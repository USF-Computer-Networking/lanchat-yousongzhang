#!/usr/bin/env python
#title           :lanchat.py
#description     :lanchat is a python tool which scans hosts of same LAN and sends text messages in UDP packets.
#author          :yousong zhang
#date            :20180225
#version         :1.0
#usage           :sudo python lanchat.py 
#python_version  :2.7.12
#==============================================================================


from pprint import pprint

import time, os, sys, logging, math
from time import sleep
import traceback
from scapy.all import *
import scan

import socket
import thread

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    # check whether user is root
    if os.geteuid() != 0:
        print("\n{0}ERROR: lanchat must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python lanchat.py{2}\n").format(RED, GREEN, END)
        notRoot = True
except:
    # then user is probably on windows
    pass
if notRoot:
    raise SystemExit

if len(sys.argv) > 1 :
    if sys.argv[1] == "-h" or sys.argv[1] == "-help" :
        print("lanchat scans hosts of same LAN and show hosts list")
        print("lanchat will listen local IP and Port (which is set by user)")
        print("lanchat send message to host when user set remore IP and Port")
        print("lanchat send message begins with: input> ")
        print("Listen and Send with default (local) IP and Port(8888), it works.")
        print("input quit to exit lanchat: input>quit")
        raise SystemExit







# retrieve network interface
def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface


# get local IP

# retrieve network interface
def getLocalIP():

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    return address






#new function
# regenerate online IPs array & configure gateway
def regenOnlineIPs():
    global onlineIPs
    global defaultGatewayMac
    global defaultGatewayMacSet

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ("{0}ScanChat{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True



# scan network
def scanNetwork():
    global hostsList
    try:
        # call scanning function from scan.py
        interface = getDefaultInterface(True)
        hostsList = scan.scanNetwork(interface)
    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.\nCatch ya later!{1}').format(GREEN, END)
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n").format(RED, END)
        raise SystemExit
    regenOnlineIPs()


# retrieve gateway IP
def getGatewayIP():
    try:
        getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return getGateway_p.src
    except:
        # request gateway IP address (after failed detection by scapy)
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP



# startListen thead
def startListenServer():
    try:
        port = input("Enter the Port to Listen(default: 8888): ")
    except:
        port = 8888
    thread.start_new_thread(startListen, (port,))




# startSend
def startSend(hosts):
    sleep(1)  # for listen finished
    local_index = len(hosts) - 1
    print("send message to host:")
    try:
        host = input("Enter the ID of Host(default: local "+ str(local_index) +"): ")
    except:
        host = local_index
    try:
        port = input("Enter the Port(default: 8888): ")
    except:
        port = 8888

    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP


    UDP_IP = hosts[host][0]
    UDP_PORT = port

    print("Ready to send message to Port : " + str(UDP_PORT) + "  @ " + UDP_IP)

    while True:
        sleep(1)
        msg = raw_input("input>")
        if msg == "quit" :
            raise SystemExit
        sock.sendto(msg, (UDP_IP, UDP_PORT))
        print("sent message to [", UDP_IP, ']:', msg)


# startListen
def startListen(port):
    host = getLocalIP()
    print("Listen Port : " + str(port)+ "  @ " + host)

    try:
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        sock.bind((host, port))

        while True:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
            print("received message from [", addr[0], ']:', data)
    except:
        # request gateway IP address (after failed detection by scapy)
        print("\n{0}ERROR: startListen failed host : "+ host +" port:" +str(port)+ ".{1}\n").format(RED, END)


# retrieve default interface MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print(
            "\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(
                RED, END)
            header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
            defaultInterfaceMac = raw_input(header)
            return defaultInterfaceMac
        else:
            return defaultInterfaceMac
    except:
        # request interface MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
        return defaultInterfaceMac


if __name__ == '__main__':
    localIP = getLocalIP();
    #pprint(localIP)
    defaultInterface = getDefaultInterface()
    #pprint(defaultInterface)
    defaultGatewayIP = getGatewayIP()
    #pprint(defaultGatewayIP)
    defaultInterfaceMac = getDefaultInterfaceMAC()
    #pprint(defaultInterfaceMac)

    global defaultGatewayMacSet
    defaultGatewayMacSet = False




    #pprint(len(sys.argv))
    #pprint(sys.argv[1])
    # commence scanning process
    scanNetwork()
    #print(type(hostsList))
    print(
        "\n{0}Using interface '{1}" + defaultInterface + "{2}' with mac address '{3}" + defaultInterfaceMac +'['+ localIP +']' + "{4}'.\nGateway IP: '{5}"
        + defaultGatewayIP + "{6}' --> {7}" + str(len(hostsList)) + "{8} hosts are found : {9}").format(GREEN, RED, GREEN, RED, GREEN,
                                                                                                RED, GREEN, RED, GREEN, END)

    hostsList.append((localIP, "local IP test"))

    print(" ID", "    IP", "       MAC")
    for index in range(len(hostsList)):

        print('[',index,']',  hostsList[index][0], hostsList[index][1])
    #pprint(hostsList);


    startListenServer()


    startSend(hostsList)

