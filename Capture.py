__author__ = 'nacho'


import dpkt
import socket
import binascii
import sys
from xml.dom import minidom


from cap_model import *

from sqlalchemy import exc,MetaData,Table

class Capture():
    def __init__(self):
        engine = create_engine('sqlite:///orm_in_detail.sqlite')
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.dbsession=Session()
        self.orphan_packets=[]
        self.__udp_packets=[]
        Base.metadata.create_all(engine)
        #self.__well_known_udp=(53,67,69,79,88,113,119,123,135,137,138,139,161,162)
        #self.__well_known_tcp=(20,21,22,25,53,110,80,443,1712)
        self.__well_known_tcp=dict()
        self.__well_known_udp=dict()
        self.__load_ports_from_xml()
        self.stats=dict()


    def open(self, fich):
        try:
            f = open(fich, "r")
            self.pcap = dpkt.pcap.Reader(f)
            self.npackets = len(list(self.pcap))
            self.processed_packets=0


            self.dbcapture = capture(filename=fich)
            self.dbsession.add(self.dbcapture)
            self.dbsession.flush()
            self.dbsession.commit()

            return 1
        except IOError:
            return 0


    def statistics(self):
        orphans=self.dbsession.query(orphan).all()
        conversations=self.dbsession.query(conversation).all()
        self.stats['id']=self.dbcapture.id
        a=self.dbsession.query(capture).filter(capture.id==self.dbcapture.id).first()
        self.stats['filename']=a.filename
        self.stats['description']=a.description
        self.stats['norphans']=len(orphans)
        self.stats['nconversations']=len(conversations)
        self.stats['bytes']=0
        self.stats['packets']=0
        self.stats['packets_tcp']=0
        self.stats['bytes_tcp']=0
        self.stats['packets_udp']=0
        self.stats['bytes_udp']=0
        self.stats['packets_other']=0
        self.stats['bytes_other']=0
        for c in conversations:
            self.stats['nconversations']+=1
            self.stats['packets']+=c.packets
            self.stats['bytes']+=c.bytes
            if c.proto==u"tcp":
                self.stats['packets_tcp']+=c.packets
                self.stats['bytes_tcp']+=c.bytes
            elif c.proto==u"udp":
                self.stats['packets_udp']+=c.packets
                self.stats['bytes_udp']+=c.bytes
            else:
                self.stats['packets_other']+=c.packets
                self.stats['bytes_other']+=c.packets
        return self.stats

    def proto_share(self,proto=u"tcp",type="packets"):
        """
        :param proto: tcp | udp
        :param type: packets | bytes
        :return: dictionary. key=proto, value=sum of type
        """
        tcp_convs=self.dbsession.query(conversation).filter(conversation.proto==proto,
                                                            conversation.capture_id==self.dbcapture.id)
        d=dict()
        for c in tcp_convs:
            if c.port in d:
                d[c.port]+=getattr(c,type)
            else:
                d[c.port]=getattr(c,type)
        return d


    def analyze(self):
        for ts,buf in self.pcap:
            r=self.analyze_packet(buf)
            a=str(self.processed_packets)+"/"+str(self.npackets)
            print "{}\r".format(a),
        # OjO aqui
        self.dbsession.commit()

    def analyze_packet(self,buf):
        eth=dpkt.ethernet.Ethernet(buf)
        self.processed_packets+=1
        packet_size=len(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
            ip = eth.data
            mac1=unicode(eth.src.encode('hex'))
            mac2=unicode(eth.dst.encode('hex'))
            ip1=unicode(socket.inet_ntoa(ip.src))
            ip2=unicode(socket.inet_ntoa(ip.dst))

            self.add_ip(ip1,mac1)
            self.add_ip(ip2,mac2)

            if ip.p==dpkt.ip.IP_PROTO_UDP or ip.p==dpkt.ip.IP_PROTO_TCP:
                if ip.p==dpkt.ip.IP_PROTO_TCP:
                    proto=u"tcp"
                elif ip.p==dpkt.ip.IP_PROTO_UDP:
                    proto=u"udp"
                else:
                    # Not TCP, not UDP
                    # save somewhere
                    pass
                data=ip.data
                port1=data.sport
                port2=data.dport

                # Check if the conversation already exists
                (c,conv)=self.__match_conversation(ip1,port1,ip2,port2,proto)
                if (c=='?'):
                    if (proto==u"tcp"):
                        # TCP lets check if is a SYN
                        if ((data.flags & dpkt.tcp.TH_SYN)!=0) and ((data.flags & dpkt.tcp.TH_ACK) ==0):
                            # Start of 3-way handshake
                            self.add_conv(ip1,ip2,proto,port2,packet_size)
                            return "SYN"
                    if mac2=="ffffffffffff":
                        # If broadcast, set server as the destination of the packet
                        self.add_conv(ip1,ip2,proto,port2,packet_size)
                        return "Broadcast"
                    if self.__is_multicast(ip2):
                        # If multicast assume the destination as the server in the conversation
                        self.add_conv(ip1,ip2,proto,port2,packet_size)
                        return "Multicast"
                    # if well known port
                    if self.__is_well_known(port1,proto):
                        self.add_conv(ip2,ip1,proto,port1,packet_size)
                        return "Port "+str(port1)
                    if self.__is_well_known(port2,proto):
                        self.add_conv(ip1,ip2,proto,port2,packet_size)
                        return "Port "+str(port2)
                    # if end of conversation matches
                    ends=self.servers
                    if (ip1,port1,proto) in ends:
                        self.add_conv(ip2,ip1,proto,port1,packet_size)
                        return "Srv "+proto+"/"*str(port1)
                    if (ip2,port2,proto) in ends:
                        self.add_conv(ip1,ip2,proto,port2,packet_size)
                        return "Srv "+proto+"/"*str(port2)

                    # if get here, then add orphan
                    self.__add_orphan(mac1,ip1,port1,mac2,ip2,port2,proto,packet_size)
                    return "o"
                else:
                    # previous conversation
                    conv.packets+=1
                    conv.bytes+=packet_size
                    self.dbsession.flush()
                    return "+"
            else:
                # Not TCP, not UDP
                pass
        else:
            # Not IP
            # Save somewhere
            pass

    def analyze_orphans(self):
        orphans=self.dbsession.query(orphan).all()
        for o in orphans:
            (c,conv)=self.__match_conversation(o.ipsrc,o.portsrc,o.ipdst,o.portdst,o.proto)
            if (c=='?'):
                ends=self.servers
                if (o.ipsrc,o.portsrc,o.proto) in ends:
                    self.add_conv(o.ipdst,o.ipsrc,o.proto,o.portsrc,packet_size)
                    return "Srv "+o.proto+"/"*str(o.portsrc)
                if (o.ipdst,o.portdst,o.proto) in ends:
                    self.add_conv(o.ipsrc,o.ipdst,o.proto,o.portdst,packet_size)
                    return "Srv "+o.proto+"/"*str(o.portdst)
                pass
            else:
                conv.packets+=1
                conv.bytes+=o.bytes
                self.dbsession.delete(o)
                self.dbsession.flush()
        # if an endpoint is in two orphans lets assume that's the server
        orphans=self.dbsession.query(orphan).all()
        cont=0
        o,orphans=orphans[0],orphans[1:]
        while len(orphans)>1:
            found=self.__match_orphan((o.ipsrc,o.portsrc,o.proto),orphans)
            if len(found)>0:
                c=self.add_conv(o.ipdst,o.ipsrc,o.proto,o.portsrc,o.bytes)
                self.dbsession.delete(o)
                for f in found:
                    c.packets+=1
                    c.bytes+=f[1].bytes
                    self.dbsession.delete(f[1])
                self.dbsession.flush()
            else:
                found=self.__match_orphan((o.ipdst,o.portdst,o.proto),orphans)
                if len(found)>0:
                    c=self.add_conv(o.ipsrc,o.ipdst,o.proto,o.portdst,o.bytes)
                    self.dbsession.delete(o)
                    for f in found:
                        c.packets+=1
                        c.bytes+=f[1].bytes
                        self.dbsession.delete(f[1])
                    self.dbsession.flush()
            cont+=1
            o,orphans=orphans[0],orphans[1:]






    def load(self,capid):
        self.dbcapture=self.dbsession.query(capture).filter(capture.id==capid).all()[0]
        pass



    @property
    def servers(self):
        p=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id).all()
        servers=[]
        for i in p:
            servers.append((i.ipdst_ip,i.port,i.proto))
        return servers

    @property
    def conversations(self):
        convs=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id).all()
        convs_list=map(lambda c: (c.ipsrc_ip,c.ipdst_ip,c.port,c.proto,c.packets,c.bytes), convs)
        return convs_list


    @property
    def orphans(self):
        orphs=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id).all()
        orphan_list=map(lambda w: (w.ipsrc,w.portsrc,w.ipdst,w.portdst,w.proto,w.packets,w.bytes), orphs)
        return orphan_list


    @property
    def captures(self):
        caps=self.dbsession.query(capture).all()
        captures=map(lambda c: (c.id,c.filename,c.description), caps)
        return captures

    @property
    def services(self):
        servs=self.dbsession.query(service).order_by(service.proto.asc(),service.port.asc()).all()
        services=map(lambda s: (s.proto,s.port,s.description), servs)
        return services

    def add_ip(self, ipa, mac):
        """Adds an IP address to the current capture"""
        #if self.dbsession.query(ip).filter(ip.ip==ipa,ip.capture_id==self.dbcapture.id).count()>0:
        a=self.dbsession.query(ip).filter(ip.ip==ipa,ip.capture_id==self.dbcapture.id).all()
        if len(a)>0:
            # Already exists
            return a[0]
        else:
            ip1 = ip(ip=ipa, mac=mac, capture_id=self.dbcapture.id)
            self.dbsession.add(ip1)
            self.dbsession.flush()
            #self.dbsession.commit()
            return ip1

    def add_conv(self,ips,ipd,proto,port,packet_size,packets=1):
        """Adds a conversation to the current capture"""
        a=self.dbsession.query(conversation).filter(conversation.ipsrc_ip==ips, conversation.ipdst_ip==ipd, \
                                                     conversation.proto==proto, conversation.port==port, \
                                                      conversation.capture_id==self.dbcapture.id).all()
        if len(a)>0:
            # Already exists
            return a[0]
        else:
            serv=self.dbsession.query(service).filter(service.port==port,service.proto==proto,
                                                      service.capture_id==self.dbcapture.id).all()
            if len(serv)==0:
                serv=service(port=port,proto=proto,capture_id=self.dbcapture.id)
                self.dbsession.add(serv)

            conv1=conversation(ipsrc_ip=ips,ipdst_ip=ipd,proto=proto,port=port, \
                               capture_id=self.dbcapture.id,packets=packets,bytes=packet_size)
            self.dbsession.add(conv1)
            self.dbsession.flush()
            return conv1

    def merge(self):
        orphans=self.dbsession.query(orphan).all()
        for o in orphans:
            self.add_conv(o.ipsrc,o.ipdst,o.proto,o.portdst,o.bytes,o.packets)
            self.dbsession.delete(o)
        self.dbsession.flush()


    def reverse_orphan(self,i):
        list=self.dbsession.query(orphan).all()
        o=list[i]
        ip,prt=o.ipsrc,o.portsrc
        o.ipsrc=o.ipdst
        o.portsrc=o.portdst
        o.ipdst=ip
        o.portdst=prt
        self.dbsession.flush()



    def __add_orphan(self,macsrc,ipsrc,portsrc,macdst,ipdst,portdst,proto,bytes):
        # check if the flow already exists
        orph=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id,
                                                 orphan.proto==proto,
                                                 orphan.ipsrc==ipsrc,orphan.portsrc==portsrc,
                                                 orphan.ipdst==ipdst,orphan.portdst==portdst).all()
        if len(orph)==1:
            orph[0].packets+=1
            orph[0].bytes+=bytes
        else:
            orph=self.dbsession.query(orphan).filter(orphan.capture_id==self.dbcapture.id,
                                                     orphan.proto==proto,
                                                     orphan.ipsrc==ipdst,orphan.portsrc==portdst,
                                                     orphan.ipdst==ipsrc,orphan.portdst==portsrc).all()
            if len(orph)==1:
                orph[0].packets+=1
                orph[0].bytes+=bytes
            else:
                # new orphan
                orph=orphan(macsrc=macsrc,ipsrc=ipsrc,portsrc=portsrc,\
                        macdst=macdst,ipdst=ipdst,portdst=portdst,
                        proto=proto,bytes=bytes,capture_id=self.dbcapture.id,packets=1)
                self.dbsession.add(orph)
        self.dbsession.flush()
        return orph


    def __match_conversation(self,ip1,port1,ip2,port2,proto):
        possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip2, \
                                      conversation.ipdst_ip==ip1, \
                                      conversation.port==port1).all()
        if len(possconv)==1:
            # found matching conversation
            return ('<',possconv[0])
        else:
            possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip1, \
                                      conversation.ipdst_ip==ip2, \
                                      conversation.port==port2).all()
            if len(possconv)==1:
                # found match in the other direction
                return ('>',possconv[0])
            else:
                # Conversation not found
                return ('?',None)

    def __match_orphan(self,ep,l):
        # looks for coincidences of the endpoints ep in l
        found=[]
        for i in l:
            ep2=(i.ipsrc,i.portsrc,i.proto)
            if ep==ep2:
                found.append(("<",i))
                l.remove(i)
                continue
            ep2=(i.ipdst,i.portdst,i.proto)
            if ep==ep2:
                found.append((">",i))
                l.remove(i)
                continue
        return found



    def __is_multicast(self,ip):
        #quadip=unicode(socket.inet_ntoa(ip))
        a=int(ip.split('.')[0])
        if a>=224 and a<=239:
            return True
        else:
            return False

    def __is_well_known(self,port,proto):
        if proto==u"tcp":
            l=self.__well_known_tcp
        else:
            l=self.__well_known_udp
        if port in l:
            return True
        else:
            return False


    def __load_ports_from_xml(self):
        xmldoc = minidom.parse('wkservices.xml')
        itemlist = xmldoc.getElementsByTagName('service')
        for s in itemlist:
            proto=s.getElementsByTagName('proto')[0].firstChild.data
            descr=s.getElementsByTagName('description')[0].firstChild.data
            port=s.getElementsByTagName('port')[0].firstChild.data
            if proto=="TCP":
                l=self.__well_known_tcp
            else:
                l=self.__well_known_udp
            l[port]=descr
