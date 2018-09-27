#RYU CONTROLLER
# Developed in association with Ayoob(UNSW)
from ryu.lib.packet import packet as ryu_packet
from scapy.all import packet as scapy_packet
from ryu.lib.packet import *
from scapy.all import *
import chardet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import MySQLdb
import re
m=[]
n=[]
c5=[]
a7=[]
db = MySQLdb.connect(host='mytestdb.clkiyezmdqnk.us-east-2.rds.amazonaws.com',user='user' ,passwd='FQGODjY7NkI1' ,db='example' ,port=3306)
# prepare a cursor object using cursor() method
cursor = db.cursor()

# execute SQL query using execute() method.
cursor.execute("""select * from URL""")

#It is going to fetch the executed mysql query into rows.
#Hence assigning it to row
row = cursor.fetchall()

#printing the result
a1=[element for tupl in row for element in tupl]
delimiters = "com", "//", "."
regexPattern = '|'.join(map(re.escape, delimiters))
for l in range(0,len(a1)):
        b=re.split(regexPattern, a1[l])
        n.append(filter(None, b))
print n
b3 = [item for sublist in n for item in sublist]
print b3
# disconnect from server
db.close()
class IcmpResponder(app_manager.RyuApp):
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        def __init__(self, *args, **kwargs):
                super(IcmpResponder, self).__init__(*args, **kwargs)
                self.hw_addr = '66:66:66:66:66:66'

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def _switch_features_handler(self, ev):
                msg = ev.msg
                datapath = msg.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                self.logger.info("switch %s connect to controller",datapath.id)
                actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,max_len=ofproto.OFPCML_NO_BUFFER)]
                inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,actions=actions)]
                mod = parser.OFPFlowMod(datapath=datapath,priority=0,match=parser.OFPMatch(),instructions=inst)
                datapath.send_msg(mod)
                mod = parser.OFPFlowMod(datapath=datapath,priority=1,match=parser.OFPMatch(udp_dst=53),instructions=inst)
                datapath.send_msg(mod)
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
                msg = ev.msg
                datapath = msg.datapath
                port = msg.match['in_port']
                pkt = ryu_packet.Packet(data=msg.data)
                self.logger.info("--------------------")
                self.logger.info("Receive Packet-in from %d",datapath.id)
                pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
                if not pkt_ethernet:
                        return
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp:
                        self._handle_arp(datapath, port, pkt_ethernet, pkt_arp)
                        return
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                if pkt_ipv4:
                        if pkt_ipv4.proto == in_proto.IPPROTO_UDP:
                                pkt_udp = pkt.get_protocol(udp.udp)
                                data = msg.data
                                self._handler_dns(datapath,pkt_ethernet,port,pkt_ipv4,pkt_udp,data)
                pkt_icmp = pkt.get_protocol(icmp.icmp)
                if pkt_icmp:
                        self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp)
                        return

        def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
                if pkt_arp.opcode != arp.ARP_REQUEST:
                        return
                pkt = ryu_packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=self.hw_addr))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac=self.hw_addr,src_ip=pkt_arp.dst_ip,dst_mac=pkt_arp.src_mac,dst_ip=pkt_arp.src_ip))
                self.logger.info("Receive ARP_REQUEST,request IP is %s",pkt_arp.dst_ip)
                self._send_packet(datapath, port, pkt)

def drop_flow(self, datapath, ip_dst):
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                match = parser.OFPMatch( ipv4_dst=ip_dst)

                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofproto.OFPFC_DELETE,
                                        out_port=ofproto.OFPP_ANY,
                                        out_group=ofproto.OFPG_ANY,
                                        match=match, instructions=inst)
                datapath.send_msg(mod)
        def _handler_dns(self,datapath,pkt_ethernet,port,pkt_ipv4,pkt_udp,data):
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                pkt_len = len(data)
                flag = data[42:44]
                b=chardet.detect(data[42:44])
                #print(b)
                if b['encoding'] == None:
                        c=flag.encode("hex")
                else:
                        flag.decode(b['encoding'])
                        c=flag.encode("hex")
                d=int(c,16)
                domain = (data[55:pkt_len-5])
                doen = chardet.detect(domain)
                d_len = len(domain)
                domain1 = domain.replace('com','')
                domain1=domain1.replace('\x03','')
                domain1=domain1.replace('www\x06','')
                m.append(domain1)
                print m
                for g in range(0,len(domain)-1):
                        if ord(domain[g])<32 or ord(domain[g])>126:
                                domain=domain[:g]+"."+domain[g+1:]
                ip_src = pkt_ipv4.dst
                ip_dst = pkt_ipv4.src
                sport = 53
                dport = pkt_udp.src_port
                a = Ether(dst=pkt_ethernet.src,src=self.hw_addr)/IP(dst=ip_dst,src=ip_src)/UDP(sport=sport,dport=dport)/DNS(opcode=0,id=d,qr=1L,rd=1L,ra=1L,aa=0L,tc=0L,z=0L,ad=0L,cd=0L,rcode=0,qdcount=1,ancount=1,nscount=1,arcount=0,qd=DNSQR(qname=domain),
an=DNSRR(rrname=domain,ttl=60,rdata=ip_src),ns=DNSRR(rrname=domain,type=2,ttl=60,rdata="ns1."+domain),ar=None)
                data = str(a)
                b5=ip_dst
                print "The Values"
                c5.append(b5)
                print type(c5)
                print c
                #if len(a7)<2:
                #       n1=list(set((c5)))
                 #      for lis in n1:
                #               if lis in a7:
                #                       print "Ignore"
                #               else:
                #                       a7.append(lis)
                #print a7
                print ip_dst
                print ip_src
                #if ip_dst in a7:
                #        actions = [parser.OFPActionOutput(port=port)]
                #else:
                #       actions=[]
                if domain1 in b3:
                        actions=[]
                else:
                        actions = [parser.OFPActionOutput(port=port)]
                out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
                datapath.send_msg(out)
                self.logger.info("Send DNS Response")


        def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
                if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
                        return
                pkt = ryu_packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=self.hw_addr))
                pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=pkt_ipv4.dst,proto=pkt_ipv4.proto))
                pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=pkt_icmp.data))
                self.logger.info("Receive ICMP_ECHO_REQUEST,request IP is %s",pkt_ipv4.dst)
                self._send_packet(datapath, port, pkt)

        def _send_packet(self, datapath, port, pkt):
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                pkt.serialize()
                if pkt.get_protocol(icmp.icmp):
                        self.logger.info("Send ICMP_ECHO_REPLY")
                if      pkt.get_protocol(arp.arp):
                        self.logger.info("Send ARP_REPLY")
                self.logger.info("--------------------")
                data = pkt.data
                actions = [parser.OFPActionOutput(port=port)]
                out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
                datapath.send_msg(out)
