from scapy.all import *

TYPE_PROBE = 0x812

class Probe(Packet):
   name = "probe"
   fields_desc = [
      IntField("s1_p2_pkt_count", 0),
      IntField("s1_p2_bytes_count", 0),

      IntField("s1_p3_pkt_count", 0),
      IntField("s1_p3_bytes_count", 0),

      IntField("total_pkt_count", 0),
      IntField("total_output_bytes", 0),

      IntField("sid", 0),

      ShortField("protocol", 0)

   ]

bind_layers(Ether, Probe, type=TYPE_PROBE)
bind_layers(Probe, IP, protocol=0x800)

