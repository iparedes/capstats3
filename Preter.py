__author__ = 'nacho'

import sys
import operator
import cmd
import Capture

from cap_model import *

from os import listdir

class Preter(cmd.Cmd):
    """Interpreter"""

    def __init__(self):
        cmd.Cmd.__init__(self)
        cmd.Cmd.prompt='>>> '
        self.cap=Capture.Capture()

    def do_quit(self,line):
        return True


    def do_open(self,fich):

        cod=self.cap.open(fich)
        if cod==1:
            print "Capture successfully loaded."
        else:
            print "Error opening capture."

    def help_open(self):
        print 'opens a pcap file'
        print 'Usage: open <file>'

    def do_ls(self,dire):
        l=listdir('.')
        print l

    def help_ls(self):
        print 'lists files in current directory'

    def do_analyze(self,cap):
        try:
            self.cap.pcap
        except Exception, e:
            return 0
        else:
            for ts,buf in self.cap.pcap:
                r=self.cap.analyze_packet(buf)
                a=str(self.cap.processed_packets)+"/"+str(self.cap.npackets)
                print "{}\r".format(a),
        # OjO aqui
        self.cap.dbsession.commit()
        print "Capture analyzed!"

    def do_show_orphans(self,line):
        orphan=self.cap.orphans
        cont=1
        for i in orphan:
            print str(cont)+") "+i[0]+":"+str(i[1])+" -> "+i[2]+":"+str(i[3])+" "+i[4]
            cont+=1

    def do_show_conversations(self,line):
        convs=self.cap.conversations
        cont=1
        for c in convs:
            print str(cont)+") "+c[0]+"->"+c[1]+str(c[2])+"/"+c[3]+" ("+str(c[4])+" packets, "+str(c[5])+" bytes)"
            cont+=1

    def do_show_services(self,line):
        servs=self.cap.services
        cont=1
        for i in servs:
            print str(cont)+") "+i[0]+"/"+str(i[1])+" "+str(i[2])
            cont+=1


    def do_analyze_orphans(self,line):
        self.cap.analyze_orphans()
        self.cap.dbsession.commit()

    def do_orphan_ports(self,line):
        self.cap.count_orphan_ports()
        print "TCP"
        print "==="
        cont=0
        for k in self.cap.orphan_tcps:
            print str(cont)+") "+str(k)+" : "+str(self.cap.orphan_tcps[k])
            cont+=1
        print "UDP"
        print "==="
        for k in self.cap.orphan_udps:
            print str(cont)+") "+str(k)+" : "+str(self.cap.orphan_udps[k])
            cont+=1

    def help_analyze(self):
        print 'analyzes the current capture'


    def do_merge(self,line):
        """Merges orphans with conversations"""
        self.cap.merge()
        self.cap.dbsession.commit()

    def do_multihomed(self,line):
        m=self.cap.multihomed
        for key in m:
            print key
            for i in m[key]:
                print "\t"+i


    def do_orphans(self,line):
        p=PreterOrphan(self.cap)
        p.cmdloop()

    def do_stats(self,line):
        p=PreterStats(self.cap)
        p.cmdloop()


    def do_list_ips(self,line):
        l=self.cap.ips()
        for i in l:
            print i

    def help_list_ips(self):
        print 'lists IP addresses present in the current capture'

    def do_list_captures(self,line):
        caps=self.cap.captures
        for id,f,des in caps:
            print str(id)+"\t("+f+"):\t"+str(des)

    def do_load_db(self,line):
        l=line.split()
        if len(l)==0:
            print "*** need to provide a capture identifier (try list_captures)"
            return
        try:
            cap_id=int(l[0])
        except ValueError:
            print "*** capture identifier should be an integer"
            return
        self.cap.load(cap_id)


class PreterOrphan(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Orphans>>> '
        self.cap=cap

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_show(self,line):
        orphan=self.cap.orphans
        print "id  Src IP           SrcPort  Dst IP           DstPort  Proto  nPkts  bytes"
        cont=1
        for i in orphan:
            c=str(cont)+")"
            print("{:<3} {:<16} :{:<7} {:<16} :{:<7} {:<6} {:<6} {:<6}".format(c,*i))
            cont+=1

    def do_reverse(self,line):
        if len(line)<1:
            print "One parameter needed:"
            print "\treverse id"
            return

        i=int(line)
        list=self.cap.orphans
        lon=len(list)
        if (i<1) or (i>lon):
            print "Id must be between 1 and "+str(lon)
        else:
            self.cap.reverse_orphan(i-1)
            self.cap.dbsession.commit()


class PreterStats(cmd.Cmd):
    def __init__(self,cap):
        cmd.Cmd.__init__(self)
        self.old_prompt=cmd.Cmd.prompt
        cmd.Cmd.prompt='Stats>>> '
        self.cap=cap
        self.cap.statistics()

    def do_quit(self,line):
        cmd.Cmd.prompt=self.old_prompt
        return True

    def do_stats(self,line):
        D=self.cap.statistics()
        print "Capture: "+str(D['id'])+" ("+D['filename']+")"
        print "Description: "+str(D['description'])
        print "Packets: "+str(D['packets'])
        print "Bytes: "+str(D['bytes'])
        print "Conversations: "+str(D['nconversations'])
        print "Orphans: "+str(D['norphans'])

    def do_protocol_stats(self,line):
        l=line.split()
        if len(l)!=2:
            print "*** need to provide two parameters:"
            print "\t (t(cp)|u(dp)) (p(ackets)|b(ytes))"
            return

        if l[1][0]=="b":
            dato="bytes"
        else:
            dato="packets"

        if l[0][0]=="u":
            proto=u"udp"
        else:
            proto=u"tcp"

        stotal=dato+"_"+proto
        total=self.cap.stats[stotal]

        s=self.cap.proto_share(proto,dato)
        sorted_s = sorted(s.items(), key=operator.itemgetter(1))

        for i in sorted_s:
            print str(i[0])+"/"+proto+" "+str(i[1])+" "+dato+" ("+str(total)+")"