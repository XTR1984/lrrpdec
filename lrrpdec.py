#!/usr/bin/python3
import time
import struct
from datetime import datetime
import os

debug = 0
def logger(s):
    print(s)
    logfile = open("lrrpdec.log","a+")
    logfile.write(str(s) + "\n")
    logfile.close()

# pcap write grabbed from https://www.bitforestinfo.com/blog/01/13/save-python-raw-tcpip-packet-into-pcap-files.html
#     Pcap Global Header Format :
#                       ( magic number + 
#                         major version number + 
#                         minor version number + 
#                         GMT to local correction +
#                         accuracy of timestamps + 
#                         max length of captured #packets, in octets +
#                         data link type) 
#
#
PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 101

class Pcap:

 def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
  self.pcap_file = open(filename, 'wb') 
  self.pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))
  logger ("[+] Link Type : {}".format(link_type))

 def writelist(self, data=[]):
  for i in data:
   self.write(i)
  return
 def write(self, data):
  ts_sec, ts_usec = map(int, str(time.time()).split('.'))
  length = len(data)
  self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
  self.pcap_file.write(data)

 def close(self):
  self.pcap_file.close()
# pcap  #################

today = datetime.today()
fname = str(today.day) + str(today.month) +  "-" + str(today.hour) + str(today.minute)
dsdpcap =  Pcap(fname  + '.pcap')

try:
    os.rename("DSDPlus.LRRP", fname+".LRRP")
except:
    pass



def writelrrp(s):
    lfile = open("DSDPlus.LRRP","a+")
    lfile.write(s)
    lfile.close()



#ip checksum grabbed from  https://stackoverflow.com/questions/1767910/checksum-udp-calculation-python
import array
def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt.append(0)
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff


def parseip(hexstr):
    logger(hexstr)
    if hexstr[:2]!="45":
        logger("ERROR: Not ip packet")
        return
    bs = ""
    try:
        bs = bytearray.fromhex(hexstr)
    except:
        logger("ERROR in hex ")
    if len(bs)<4:
        logger("ERROR in size")
        return
    plen = int.from_bytes(bs[2:4], "big")
    logger("iplen = %d"  %(plen))
    if  len(bs) < plen:
        logger("ERROR in IP packet length")
        return
    dsdpcap.write(bs[:plen])
    if checksum(bs[:20])!=0:
        logger("ERROR in IP header checksum ")
        return
    src = int.from_bytes(bs[13:16], "big")        
    srcip = list(map(str, bs[12:16]))
    srcip = ".".join(srcip)        
    dstip = list(map(str, bs[16:20]))
    dstip = ".".join(dstip)
    if bs[9] == 1: #ICMP
        logger("ICMP protocol")   
    if bs[9] == 17: #UDP protocol
        #pseudoudp = bs[12:20] + [0,17] + 
        udpdata = bs[28:]
        udplength = int.from_bytes(bs[24:26], "big")
        if len(udpdata)!= udplength - 8:
            logger("ERROR in udp length")
            return
        
        srcport=int.from_bytes(bs[20:24], "big")
        destport=int.from_bytes(bs[22:24],"big")
        if destport == 4005:   #ARS
            logger("ARS src = %d" %(src))
        elif destport == 4001: #LRRP
            lrrpdecoder(src, udpdata)
        elif destport == 4007: #TMS
            msg = udpdata[6:]
            msg = msg.decode(encoding="UTF-16") 
            logger("TMS src=%s dest=%s msg=%s" %(srcip,dstip,msg))
            
        else:
            logger("Unknown port %d" %(destport))

    pass
    
def lrrpdecoder(src, udpdata):
    try:
        if list(udpdata[:3]) == [0x09, 0x0E, 0x22]:
            logger("Unknown LRRP?")
        elif list(udpdata[:3]) == [0x0d, 0x15, 0x22]:
            decoder1(src, udpdata)   #скорые
        elif list(udpdata[:3]) == [0xd, 0x08, 0x22]:
            logger("LRRP Control ACK  SRC=%d"  %(src)) #size 10   
        elif list(udpdata[:3]) == [0xb, 0x07, 0x22]:  #size 37
            logger("LRRP Control ACK  SRC=%d"  %(src))                
        elif list(udpdata[:3]) == [0xd, 0x1A, 0x22]:
            decoder2(src,udpdata)
        else: 
            logger("unknown")
    except Exception as e:
        logger(e)


def decoder1(src, udpdata):  
                    lat = ""
                    long = ""
                    speed = 0
                    az = 0
                    latraw = int.from_bytes(udpdata[8:12],"big")
                    longraw = int.from_bytes(udpdata[12:16],"big")
                    courseraw = int.from_bytes(udpdata[22:23],"big")
                    speedrawh = int.from_bytes(udpdata[19:20],"big")
                    speedrawl = int.from_bytes(udpdata[20:21],"big")
                    lat = latraw*180/0xFFFFFFFF
                    long = longraw*360/0xFFFFFFFF
                    speed = (speedrawh + speedrawl/128.0)*3.6  # км/час
                    course = courseraw*2
                    today = datetime.today()
                    s = today.strftime("%Y/%m/%d %H:%M:%S") + "   " + str(src) + " " + f'{lat:.5f}' + " " + f'{long:.5f}' + " " + f'{speed:.3f}' + " " + str(course) + "\n"
                    logger(s)
                    writelrrp(s)

def decoder2(src, udpdata):  
                    lat = ""
                    long = ""
                    speed = 0
                    az = 0
                    latraw = int.from_bytes(udpdata[15:19],"big")
                    longraw = int.from_bytes(udpdata[19:23],"big")
                    #courseraw = int.from_bytes(udpdata[22:23],"big")
                    courseraw = 0
                    speedrawh = int.from_bytes(udpdata[26:27],"big")
                    speedrawl = int.from_bytes(udpdata[27:28],"big")
                    lat = latraw*180/0xFFFFFFFF
                    long = longraw*360/0xFFFFFFFF
                    speed = (speedrawh + speedrawl/128.0)*3.6  # км/час
                    course = courseraw*2
                    today = datetime.today()
                    s = today.strftime("%Y/%m/%d %H:%M:%S") + "   " + str(src) + " " + f'{lat:.5f}' + " " + f'{long:.5f}' + " " + f'{speed:.3f}' + " " + str(course) + "\n"
                    logger(s)
                    writelrrp(s)




#key1 =  "Data 45 00 00 "
#key11 = "Data 45 80 00 "
key2 =  "Data "
key3 =  "Rate "
gcounter = -1
slot1state=0
slot2state=0
src = 0
slot = 0

slot1data = ""
slot2data = ""
with open('../DSD.log','r') as f:
    while True:
        for line in f:
            gcounter +=1
            if "FAIL" in line:
                continue
            if "slot1" in line[:30]:
                  slot = 1
            elif "slot2" in line[:30]: 
                  slot = 2
            else:
                  slot = 0
            if debug:
                logger("gc = %d, slot = %d, slot1state = %d slot2state = %d slot1data = %s slot2data=%s"  %(gcounter,slot, slot1state,slot2state,slot1data, slot2data))
            if slot1state == 0 and slot == 1 and "Rate" in line and "Data" in line:
                    slot1state = 1
                    slot1data = ""

            if slot2state == 0 and slot == 2 and "Rate" in line and "Data" in line:
                    slot2state = 1
                    slot2data = ""

            if slot1state == 1 and slot == 1:
                 if not "Rate" in line:
                     slot1state = 0
                     parseip(slot1data)
                     slot1data = ""
                     continue

                 i = line.find("Data ")            
                 i2 = line[i+4:].find("  ") 
                 err = line[i:].find("ERR")
                 if i == -1 or i2 == -1 or err>0 :
                     state = 0
                     slot1data = ""
                     continue
                 hex1 = line[i+4:i+4+i2]
                 hex1 = hex1.replace(" ","")
                 slot1data = slot1data + hex1

            if slot2state == 1 and slot == 2:
                 if not "Rate" in line:
                     slot2state = 0
                     parseip(slot2data)
                     slot2data = ""
                     continue

                 i = line.find("Data ")            
                 i2 = line[i+4:].find("  ") 
                 err = line[i:].find("ERR")
                 if i == -1 or i2 == -1 or err>0 :
                     state = 0
                     slot2data = ""
                     continue
                 hex2 = line[i+4:i+4+i2]
                 hex2 = hex2.replace(" ","")
                 slot2data = slot2data + hex2     
               
        time.sleep(1)        


