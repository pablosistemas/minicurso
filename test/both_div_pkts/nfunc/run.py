#!/bin/env python

from NFTest import *

phy2loop0 = ('../connections/conn', [])

nftest_init(sim_loop = [], hw_config = [phy2loop0])
nftest_start()
#nftest_fpga_reset()

# send and receive 1 via port 1
DA = "00:11:11:11:11:11"
SA = "00:22:22:22:22:22"

DST_IP = '192.168.0.1'
SRC_IP = '192.168.0.2'
TTL = 64

port1 = 80
port2 = 20

#pkt = make_IP_pkt(dst_MAC = DA, src_MAC = SA, dst_IP = '192.168.0.1',
#                  src_IP = '192.168.0.2', pkt_len = 60)

load = ''
lengthh = 64
for genr in range(lengthh):
   load += chr(randint(0,255))

pt = [1,3,5,7]
typePkt = []
j=0
numPkts=10
seqnum=[]
for ii in range(numPkts):
   for i in range(4):
      DA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1])
      SA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i])
      DST_IP = '192.168.0.%x'%pt[i-1]
      SRC_IP = '192.168.0.%x'%(pt[i])
      if i in [0,2]:
         hdr=scapy.TCP()
         hdr.sport=port1
         hdr.dport=port2
         pkt = scapy.Ether(dst=DA, src=SA)/scapy.IP(dst=DST_IP, src=SRC_IP,
                  ttl=TTL)/hdr/load
         pkt.len = len(load)
         seqnum.append((pkt.seq+pkt.len+1))
      else:
         pkt = make_ICMP_request_pkt(dst=DA, src=SA, dst_IP=DST_IP, src_IP=SRC_IP, pkt_len=60)
         seqnum.append(0)

      j=j+1

      nftest_send_phy('nf2c'+str(i), pkt)
      nftest_expect_dma('nf2c'+str(i), pkt)

nftest_barrier()

#ACK+DATA
DST_IP = '192.168.0.2'
SRC_IP = '192.168.0.1'
j=0
for ii in range(numPkts):
   for i in range(4):
      DA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1])
      SA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i])
      DST_IP = '192.168.0.%x'%pt[i-1]
      SRC_IP = '192.168.0.%x'%(pt[i])
      if i in [0,2]:
         hdr=scapy.TCP()
         hdr.sport=port2
         hdr.dport=port1
         hdr.seq = seqnum[j]
         hdr.ack = seqnum[j]
         hdr.flags = 0b10000
         pkt = scapy.Ether(dst=DA, src=SA)/scapy.IP(dst=DST_IP,
                   src=SRC_IP,ttl=TTL)/hdr/load
         pkt.len = len(load)
         seqnum[j] = pkt.ack+pkt.len+1
      else:
         pkt = make_ICMP_request_pkt(dst=DA, src=SA, 
                  dst_IP=DST_IP, src_IP=SRC_IP, pkt_len=60)
         seqnum[j]=0

      j=j+1

      nftest_send_phy('nf2c'+str(i), pkt)
      nftest_expect_dma('nf2c'+str(i), pkt)


nftest_barrier()

#ACK do ACK
DST_IP = '192.168.0.1'
SRC_IP = '192.168.0.2'
j=0
#for i in pt:
for ii in range(numPkts):
   for i in range(4):
      DA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i-1],
         pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1],pt[i-1])
      SA = "00:%x%x:%x%x:%x%x:%x%x:%x%x"%(pt[i],
         pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i],pt[i])
      DST_IP = '192.168.0.%x'%pt[i-1]
      SRC_IP = '192.168.0.%x'%(pt[i])
      if i in [0,2]:
         hdr=scapy.TCP()
         hdr.sport=port1
         hdr.dport=port2
         hdr.seq = seqnum[j]
         hdr.ack = seqnum[j]
         hdr.flags = 0b10001
         pkt = scapy.Ether(dst=DA, src=SA)/scapy.IP(dst=DST_IP, 
                  src=SRC_IP,ttl=TTL)/hdr/load
         pkt.len = len(load)
         seqnum[j] = pkt.ack+pkt.len+1
      else:
         pkt = make_ICMP_request_pkt(dst=DA, src=SA, dst_IP=DST_IP, src_IP=SRC_IP, pkt_len=60)
         seqnum[j]=0

      j=j+1

      nftest_send_phy('nf2c'+str(i), pkt)
      nftest_expect_dma('nf2c'+str(i), pkt)

nftest_finish()
