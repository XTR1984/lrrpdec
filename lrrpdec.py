#!/usr/bin/python3
# disclaimer: 
# скрипт написан с учебно-исследовательской целью, автор ни в коем случае не призывает и не планирует 
# использовать во вред полученную с помощью скрипта информацию

# настройки
DEBUG = 0
UDPCHECKSUM = 1    #проверять контрольную сумму UDP данных
SEEK2LOGEND = 1    #встаём в конец лога DSD
MOVEOLD     = 0    #обнулять и перемещать *.lrrp и *.pcap в OLD при запуске
SENDUDP     = 0    #отправлять udp пакеты в сеть
SEND2IP    = "192.168.168.165"

import time
import struct
from datetime import datetime
import os
import queue
import sys
import socket


try:
    import specdecoder
except Exception as e:
    logger.write(e)


#класс логирования вывода
class Logger:
    def  __init__(self):
        self.logfile = open("lrrpdec.log","a+")
    def write(self, s):
        print(s)
        try:
            self.logfile.write(str(s) + "\n")
        except Exception as e:
            print(e)
    def close(self):
        self.logfile.close()

logger = Logger()

#класс записи в pcap
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
  #logger ("[+] Link Type : {}".format(link_type))

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


#
today = datetime.today()
fname = f'{today.day:02d}{today.month:02d}-{today.hour:02d}{today.minute:02d}{today.second:02d}'

if not os.path.exists("OLD"):
    os.makedirs("OLD")

if not os.path.exists("../DSD.log"):
    logger.write("Не найден ../dsd.log. ")
    sys.exit()

if MOVEOLD:
    try:
        if os.path.getsize("DSDPlus.LRRP")>0:
            os.rename("DSDPlus.LRRP", "OLD/" + fname + ".LRRP")
    except:
        pass
    try:
        if os.path.getsize("lrrpdec.pcap")>0:
            os.rename("lrrpdec.pcap", "OLD/" + fname + ".pcap")
    except:
        pass


dsdpcap =  Pcap("lrrpdec.pcap")


#класс записи LRRP данных
class lrrpwriter:
    def __init__(self,filename="DSDPlus.LRRP"):
        self.queue = queue.Queue()
        self.firstwrited = True;
        self.first = ""
    def write(self,str):
        self.queue.put(str)
    def flush(self):
            while( not self.firstwrited):
                try:
                    lfile = open("DSDPlus.LRRP","a+")
                    lfile.write(s)
                    lfile.close()    
                    self.firstwrited = True
                except:
                    pass
                time.sleep(0.1)
            try:
                lfile = open("DSDPlus.LRRP","a+")      
                while not self.queue.empty():           
                     self.firstwrited = False
                     self.first = self.queue.get_nowait()
                     lfile.write(self.first)
                     self.firstwrited = True
                lfile.close()    
            except:
                pass


#def writelrrp(s):
#    lfile = open("DSDPlus.LRRP","a+")
#    lfile.write(s)
    #lfile.close()

lrrpwriter = lrrpwriter()

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


                

# разбираем выхваченные IP-пакеты по протоколам и декодерам, пишем pcap
def parseip(hexstr):
    if len(hexstr)<1:
        return
    logger.write(hexstr)
    if hexstr[:2]!="45":
        logger.write("ERROR: Not ip packet")
        return
    bs = ""
    try:
        bs = bytearray.fromhex(hexstr)
    except:
        logger.write("ERROR in hex ")
        return
    if len(bs)<20:
        logger.write("ERROR in IP packet length")
        return
    plen = int.from_bytes(bs[2:4], "big")
    logger.write("iplen = %d"  %(plen))
    if  len(bs) < plen:
        logger.write("ERROR in IP packet length")
        return
    dsdpcap.write(bs[:plen])
    if checksum(bs[:20])!=0:
        logger.write("ERROR in IP header checksum ")
        return
    src = int.from_bytes(bs[13:16], "big")        
    srcip = list(map(str, bs[12:16]))
    srcip = ".".join(srcip)        
    dstip = list(map(str, bs[16:20]))
    dstip = ".".join(dstip)
    if bs[9] == 1: #ICMP
        logger.write("ICMP protocol srcip=%s destip=%s" %(srcip,dstip) )   
    if bs[9] == 17: #UDP protocol
        udpdata = bs[28:]
        bs_udplength = bs[24:26]
        bs_udpchecksum = bs[26:28]
        udplength = int.from_bytes(bs_udplength, "big")
        if len(udpdata)!= udplength - 8:
            logger.write("ERROR in udp length")
            return
        bs_srcport = bs[20:22]
        bs_destport = bs[22:24]
        srcport=int.from_bytes(bs_srcport, "big")
        destport=int.from_bytes(bs_destport,"big")

        if UDPCHECKSUM:
            #pseudoudp src dest 0 proto udplen srcport srcdest datalen checksum data
            bs_srcdest = bs[12:20]
            proto = b'\x00\x11'
            pseudopacket = bs_srcdest + proto + bs_udplength + bs_srcport + bs_destport + bs_udplength + bs_udpchecksum + udpdata
            checksuma = checksum(pseudopacket)
            #checksumh = int.from_bytes(bs_udpchecksum,"big")
            #logger.write("SUM = %d  in header = %d" %(checksuma, checksumh))            
            if checksuma !=0:
                logger.write("ERROR in UDP checksum")
                return
        
        if SENDUDP:
            sendudp(destport,udpdata)

        today = datetime.today()
        time = today.strftime("%Y/%m/%d %H:%M:%S")

        if destport == 4005:   #ARS      #45010028082300004011D0F60C008CB60DFAFAFA 0FA50FA50014E0F0 000AF0400533363032320000
            logger.write("%s ARS src = %d srcip=%s destip = %s" %(time,src,srcip,dstip))
        elif destport == 4001: #LRRP
            lrrpdecoder(src, udpdata)
        elif destport == 4007: #TMS
            try:
                msg = udpdata[6:]
                msg = msg.decode(encoding="UTF-16") 
                logger.write("%s TMS src=%d srcip=%s destip=%s msg=%s" %(time, src, srcip,dstip,msg))
            except Exception as e:
                logger.write(e)
                pass
        elif destport == 4104: #SB
            if 'specdecoder' in sys.modules:
                r = specdecoder.decoder4104(src,udpdata,logger,lrrpwriter)
            else:
                logger.write("SB")

        else:
            logger.write("Unknown UDP port %d. SRC = %d, srcip = %s, destip = %s " %(destport,src,srcip,dstip))

    pass

def sendudp(destport, udpdata):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.sendto(udpdata, (SEND2IP, destport))


#разбор основных lrrp данных    
LRRPPacketTypes =        { 0x05 : "ImmediateLocationRequest",
                           0x07 : "ImmediateLocationResponse", 
                           0x09 : "TriggeredLocationStartRequest",
                           0x0B : "TriggeredLocationStartResponse",
                           0x0D : "TriggeredLocationData",
                           0x0F : "TriggeredLocationStopRequest",
                           0x11 : "TriggeredLocationStopResponse",
                           0x14 : "ProtocolVersionRequest",
                           0x15 : "ProtocolVersionResponse"
                         }
def lrrpdecoder(src,udpdata):
        result = parselrrp(udpdata)
        logger.write(f"  {'Source':15} : {str(src):10}")
        today = datetime.today()
        time = today.strftime("%Y/%m/%d %H:%M:%S")
        logger.write(f"  {'LocalTime':15} : {time}")
        #if "Error" in result:
        #    logger.write("  ERROR:" + result["Error"])
        #else:
        for key in result:
                logger.write(f"  {key:15} : {str(result[key]):10}")
        if "Latitude" in result:

            lrrpstring = today.strftime("%Y/%m/%d %H:%M:%S") + "   "  + str(src) + " " 
            lrrpstring +=  f'{result["Latitude"]} {result["Longitude"]} '
            if "Speed" in result:
                lrrpstring += f'{result["Speed"]} ' 
            else:
                lrrpstring += "0.0 "                
            if "Direction" in result:
                lrrpstring += f'{result["Direction"]} '
            else:
                lrrpstring += "0.0 "
            lrrpwriter.write(lrrpstring + "\n")


def parselrrp(udpdata):
    result = {}
    i = 0
    try:    
        packettype = udpdata[i]
        if not packettype in LRRPPacketTypes:
            result["Error"] = "Unknown packet type" 
            return result
        else:
            result["PacketType"] =  LRRPPacketTypes[packettype]
        if udpdata[2] != 0x22:
            result["Error"] = "Not LRRP data"
            return result
        #result["Data"]= {}
        reqidlen = udpdata[3]
        requestID = int.from_bytes(udpdata[4:4+reqidlen], "big")
        result["requestID"] = str(requestID)

        i = 4 + reqidlen
        if packettype == 0xd or packettype==0x7 or packettype==0xb or packettype==0x11 :#LocationData and resp
            while(i<len(udpdata)):
                    t = udpdata[i]  
                    i += 1
                    if t == 0x51:
                        latraw = int.from_bytes(udpdata[i:i+4],"big")
                        longraw = int.from_bytes(udpdata[i+4:i+8],"big")
                        radiusraw = readFloat(udpdata[i+8:i+10])
                        result["Latitude"]  = f'{latraw*180/0xFFFFFFFF:.5f}'
                        result["Longitude"] = f'{longraw*360/0xFFFFFFFF:.5f}'
                        result["Radius"]    = f'{radiusraw:.2f}'
                        i += 10

                    elif t == 0x34:
                        result["RemoteTime"] = readDateTime(udpdata[i:i+5])
                        i += 5
                    elif t == 0x37:
                        responseCode = int.from_bytes(udpdata[i:i+1], "big")
                        i += 2
                        if responseCode & 0x80 != 00:
                            responseCode = responseCode << 7 + udpdata[i]
                            i += 1            
                        result["ResponseCode"] = str(responseCode)
                    elif t == 0x38:
                        responseCode = 0
                        result["ResponseCode"] = str(responseCode)
                    elif t == 0x55:
                        latraw = int.from_bytes(udpdata[i:i+4],"big")
                        longraw = int.from_bytes(udpdata[i+4:i+8],"big")
                        radius = readFloat(udpdata[i+8:i+10])
                        altitude = readFloat(udpdata[i+10:i+12])
                        accuracy = readFloat(udpdata[i+12:i+14])
                        result["Latitude"]  = f'{latraw*180/0xFFFFFFFF:.5f}'
                        result["Longitude"] = f'{longraw*360/0xFFFFFFFF:.5f}'
                        result["Radius"]    = f'{radius:.2f}'
                        result["Altitude"] = f'{altitude:.2f}'
                        result["Accuracy"] = f'{accuracy:.2f}'
                        i += 14
                    elif t == 0x56:
                        direction = int.from_bytes(udpdata[i:i+1],"big")*2
                        result["Direction"] = str(direction)
                        i += 1
                    elif t == 0x66:
                        latraw = int.from_bytes(udpdata[i:i+4],"big")
                        longraw = int.from_bytes(udpdata[i+4:i+8],"big")
                        result["Latitude"]  = f'{latraw*180/0xFFFFFFFF:.5f}'
                        result["Longitude"] = f'{longraw*360/0xFFFFFFFF:.5f}'
                        i += 8
                    elif t == 0x69:
                        latraw = int.from_bytes(udpdata[i:i+4],"big")
                        longraw = int.from_bytes(udpdata[i+4:i+8],"big")
                        radius = readFloat(udpdata[i+8:i+10])
                        altitude = readFloat(udpdata[i+10:i+12])
                        result["Latitude"]  = f'{latraw*180/0xFFFFFFFF:.5f}'
                        result["Longitude"] = f'{longraw*360/0xFFFFFFFF:.5f}'
                        result["Altitude"] = f'{altitude:.2f}'
                        i += 4+4+2
                    elif t == 0x6C:
                        speedraw  = readFloat(udpdata[i:i+2])
                        speed = (speedraw)*2.23  # mph
                        result["Speed"] = f'{speed:.3f}'
                        i += 2
                    else:
                        result["Error"] = f"Unknown LRRP tag {t:#x}" 
                        return result
        if packettype == 0x5 or packettype==0x9:  # request
            params = ""
            while(i<len(udpdata)):
                t = udpdata[i]
                i +=1
                if t==0x34:   #todo непонятка
                    params += "TrigPeriod "
                    if udpdata[i] == 0x31: 
                        params += "0x31 "
                        i+=2
                    elif udpdata[i] == 0x78:
                        params += "OnMove "
                        i+=2
                elif t==0x42:
                    params += "GPIO "
                elif t==0x50:
                    params += "Accur "
                elif t==0x51:
                    params += "Accur Time "
                elif t==0x52:
                    params += "Time "
                elif t==0x54:
                    params += "Alt "
                elif t==0x57:
                    params += "Dir "
                else:
                    params += "UnkTag "
            result["ReqParams"] = params

                    

    except Exception as e:
        logger.write(e)
    return result    
                    
def readFloat(bs):
    f = int(bs[0])
    f += int(bs[1])*0.01
    return f

def readDateTime(bs):
        year  = bs[0]<<6 | ( bs[1] >> 2 & 0x3f)
        month = (bs[1]&3)<<2 | bs[2]>>6 & 3
        day = bs[2] >>1 & 31
        hour = ((bs[2] & 1) << 4) | (bs[3] >> 4 & 0xf)
        minute  = (bs[3] & 15) << 2 | bs[4] >> 6 & 3
        second = bs[4] & 0x3f
        dt = datetime(year,month,day,hour,minute,second)
        return dt.strftime("%Y/%m/%d %H:%M:%S")
    
 #090E22040000000151 42822C62343178
 #0D152203000001 51 4BDE538F3B94F1E6 02436C0000561E
 #0D0722030000013710
 #0D082204000000013710
 #0D1A220400000001341F973280C6 51 4BE8AED73B882B46 0352 6C 0215



#основной цикл по логу DSD, выхватываем hex данные и отправляем в разбор
today = datetime.today()
s= today.strftime("%Y/%m/%d %H:%M:%S")
logger.write("Script started " + s)
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
    if SEEK2LOGEND:
        f.seek(0,2)
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
            if DEBUG:
                logger.write("gc = %d, slot = %d, slot1state = %d slot2state = %d slot1data = %s slot2data=%s"  %(gcounter,slot, slot1state,slot2state,slot1data, slot2data))
            if slot1state == 0 and (slot == 1 or "MS DATA" in line) and ("Rate" in line and "Data" in line):
                    slot1state = 1
                    slot1data = ""

            if slot2state == 0 and slot == 2 and "Rate" in line and "Data" in line:
                    slot2state = 1
                    slot2data = ""

            if slot1state == 1 and slot == 1 or "MS DATA" in line:
                 if not "Rate" in line:
                     slot1state = 0
                     parseip(slot1data)
                     slot1data = ""
                     continue

                 i = line.find("Data ")            
                 i2 = line[i+4:].find("  ") 
                 err = line[i:].find("ERR")
                 if i == -1 or i2 == -1 or err>0 :
                     slot1state = 0
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
                     state2state = 0
                     slot2data = ""
                     continue
                 hex2 = line[i+4:i+4+i2]
                 hex2 = hex2.replace(" ","")
                 slot2data = slot2data + hex2     
        lrrpwriter.flush()               
        time.sleep(1)        


