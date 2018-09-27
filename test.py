from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6
from ryu.lib import mac


class SimpleARPProxy13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleARPProxy13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

    def add_flow1(self, datapath, ipv4_dst,mask, actions,priority):
        ofproto = datapath.ofproto
        #print ipv4_dst
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800,ipv4_dst=(ipv4_dst,mask))
        #print ipv4_dst
        print(actions)
        inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match,cookie=0,command=ofproto.OFPFC_ADD,priority=priority, instructions=inst)
        datapath.send_msg(mod)
    def add_flow(self, datapath,priority):
        ofproto = datapath.ofproto
        #print ipv4_dst
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800)
        #out_port=3
        #actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]

        #print ipv4_dst
        #print(actions)
        inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,[])]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match,cookie=0,command=ofproto.OFPFC_ADD,priority=priority,flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        id1=hex(datapath.id)
        id2=16-(len(id1[2:]))
        id=('0'*id2)+id1[2:]
        datapath.id=id
        dpid1=[]
        K=4
        pod=id[11]
        switch=id[13]
        host=id[15]
        csrul=[]
        Aggrul=[]
        Aggrul1=[]
        Edgerul=[]
        Edgerul1=[]

        if int(pod) == K:
            for i in range(K):
                csrul.append('10.'+'%s'%i+'.0.0')
                mask='255.255.0.0'
                out_port=i+1
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]
                priority=100
                self.add_flow1(datapath=datapath,ipv4_dst=csrul[i],mask=mask,actions=actions,priority=priority)

        elif int(pod)<K & (int(switch)>((K/2))):
            j=0#Aggswitches
            while j<(K/2):
                print id
                Aggrul.append('10.'+'%s.'%pod+'%s'%j+'.0')
                mask='255.255.255.0'
                priority=100
                out_port=j+1
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow1(datapath=datapath,ipv4_dst=Aggrul[j],mask=mask,actions=actions,priority=priority)
                Aggrul1.append('0.0.0.'+'%s'%(K/2+j))
                mask='0.0.0.255'
                b=int(switch)
                out_port=((j-2+b)%(K/2))+1 #Here our ports re from 1 to 4
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]
                priority=10
                self.add_flow1(datapath=datapath,ipv4_dst=Aggrul1[j],mask=mask,actions=actions,priority=priority)
                j=j+1

        else:
            l=0
            while l<(K/2):
                print id
                Edgerul.append('10.'+'%s.'%(int(pod))+'%s'%(int(switch)-1)+'.%s'%(l+K/2))
                mask='255.255.255.255'
                priority=100
                out_port=(l+(K/2))+1
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]
                print Edgerul
                self.add_flow1(datapath=datapath,ipv4_dst=Edgerul[l],mask=mask,actions=actions,priority=priority)
                Edgerul1.append('0.0.0.'+'%s'%(K/2+l))
                b=int(switch)
                out_port=((l-2+b)%(K/2))+1#Here our ports re from 1 to 4
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]
                priority=10
                mask='0.0.0.255'
                print Edgerul[l]
                print out_port
                self.add_flow1(datapath=datapath,ipv4_dst=Edgerul1[l],mask=mask,actions=actions,priority=priority)
                l=l+1
