# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# by SienTar
# Last Updated: 2023.10

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
#from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
import time
import binascii
import socket

import setting

# 定义SDN_Monitor应用
class SDN_Monitor(app_manager.RyuApp):

    # OpenFLow版本：1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # 初始化应用
    def __init__(self, *args, **kwargs):
        super(SDN_Monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # 记录MAC地址与交换机端口的映射关系
        self.packet_out_msg = None # 用于存储Packet-Out消息

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.168.95.27', 80)) # 指定SDN网段内可访问的IP地址
        self.local_ip = s.getsockname()[0] # 获取本机在SDN网段内的IP地址
        #print('mydebug: self.local_ip:', self.local_ip)

        self.datapaths = {} # 记录数据路径（交换机）信息
        self.port_features = {} # 记录交换机端口特性
        self.port_stats = {} # 记录交换机端口状态
        self.port_speed = {} # 记录交换机端口数据传输速度
        self.ipv4_to_port = {} # 记录IPv4地址与交换机端口的映射关系
        self.port_free_bw = {} # 记录交换机端口剩余带宽
        self.port_osd_info = {} # 记录交换机端口对应主机的OSD信息
        self.ipv4_osd_info = {} # 记录IPv4地址对应主机的OSD信息

        self.packet_in_triggered = False # 用于标记Packet-In触发

        self.monitor_thread = hub.spawn(self._main) # 启动一个绿色线程来执行self._main函数

    # 本Ryu应用主函数，定期发送Packet-Out消息并更新self.port_features
    def _main(self):
        if_packet_out = False
        if_port_features = False
        if_nothing_happened = False
        period_packet_out = 1
        period_port_features = 1
        period_nothing_happened = period_packet_out + period_port_features

        # 定期发送Packet-Out消息并更新self.port_features
        while True:
            # 定期将self.ipv4_osd_info内保存的OSD信息作为Packet-Out消息发送至self.packet_out_msg的来源处
            if (self.packet_out_msg is not None) and (len(self.ipv4_osd_info) != 0):
                print('mydebug: self.ipv4_osd_info:', self.ipv4_osd_info)
                self._packet_out_handler(self.packet_out_msg, self.ipv4_osd_info)

                if not if_packet_out:
                    if_packet_out = True

                # 休眠
                self._sleep_with_countdown(period_packet_out)

            # 向self.port_features填入以DPID（作为key），并发送请求消息到交换机以获取一些统计信息
            if self.datapaths:
                for dp in self.datapaths.values():
                    if dp.id not in self.port_features.keys():
                        self.port_features.setdefault(dp.id, {})
                    self._request_stats(dp)
                    #print('mydebug: self.port_features:',self.port_features)
                print('mydebug: self.port_features updated.')

                if not if_port_features:
                    if_port_features = True

                # 休眠
                self._sleep_with_countdown(period_port_features)

            # 如果上述两项操作均未得到执行则休眠，以免无间隔的无限空循环阻断Ryu应用其他操作
            if (not if_packet_out) and (not if_port_features):
                if not if_nothing_happened:
                    print('\nmydebug: Nothing happened yet. Waiting for something to happen...')
                    if_nothing_happened = True
                time.sleep(period_nothing_happened)

    # 将data通过Packet-Out消息发往消息msg的来源处
    def _packet_out_handler(self, msg, data):
        # 编码data
        data = str(data)
        data = data.encode('utf-8')
        data = binascii.b2a_hex(data)
        print('mydebug: Hex data:', data)

        # 从消息msg中获取各项信息
        datapath = msg.datapath # 获取交换机信息
        ofproto = datapath.ofproto # 获取OpenFlow版本
        ofproto_parser = datapath.ofproto_parser # 解析OpenFlow消息
        dpid = datapath.id # 获取交换机的DPID
        print('mydebug: dpid:', dpid)

        # 配置Packet-Out所需参数
        pkt = packet.Packet(msg.data) # 利用消息msg的数据创建数据包
        eth_header = pkt.get_protocols(ethernet.ethernet)[0] # 获取数据包的以太网信息
        dst_mac = eth_header.src # 设置目的MAC地址为数据包源MAC地址
        print('mydebug: dst_mac:', dst_mac)
        out_port = self.mac_to_port[dpid][dst_mac] # 设置发出端口为目的MAC地址对应的端口
        print('mydebug: out_port:', out_port)
        if (dpid, out_port) not in self.ipv4_to_port.keys(): # 获取到目标地址前，不执行Packet-Out操作
            print('mydebug: IPv4 address of ' + str((dpid, out_port)) + ' hasn\'t been added to self.ipv4_to_port.')
            return
        dst_ip = self.ipv4_to_port[(dpid, out_port)] # 设置目的IP地址为发出端口对应的IP地址
        print('mydebug: dst_ip:', dst_ip)
        eth_instance = ethernet.ethernet(dst = dst_mac, src = '01:23:45:67:89:ab') # 创建以太网实例, 目的MAC地址使用dst_mac，源MAC地址使用虚构地址
        ipv4_instance = ipv4.ipv4(src = self.local_ip, dst = dst_ip, proto = 17) # 创建IPv4实例，源IP地址使用本机IP地址self.local_ip，目的IP地址使用dst_ip
        udp_instance = udp.udp(src_port = 19045, dst_port = 22631) # 创建UDP实例，源端口和目的端口均使用虚拟端口号

        # 创建新的数据包，载入各项协议以及数据并发包
        pkt = packet.Packet()
        pkt.add_protocol(eth_instance)
        pkt.add_protocol(ipv4_instance)
        pkt.add_protocol(udp_instance)
        pkt.add_protocol(data)
        pkt.serialize()
        actions = [ofproto_parser.OFPActionOutput(out_port)]
        req = ofproto_parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions,
                                          data=pkt.data)
        datapath.send_msg(req)
        print('mydebug: Packet-Out finished.')

    # 通过ofp_event.EventOFPSwitchFeatures事件触发流表项增加，并记录交换机信息
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # 记录交换机信息
        if not datapath.id in self.datapaths.keys():
            self.datapaths.setdefault(datapath.id, None)
        self.datapaths[datapath.id] = datapath
        #print('mydebug: self.datapaths:', self.datapaths)
        print('\n\nmydebug: self.datapaths updated.\n')

    # 增加流表项
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # 通过ofp_event.EventOFPPacketIn事件触发Packet-In处理
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        if not self.packet_in_triggered:
            print('\n\nmydebug: Packet-In has been triggered.\n') # 输出Packet-In已触发的消息
            self.packet_in_triggered = True

        msg = ev.msg # 获取Packet-In事件的消息
        datapath = msg.datapath # 获取数据路径（交换机）
        #ofproto = datapath.ofproto
        #parser = datapath.ofproto_parser
        dpid = datapath.id # 获取交换机的DPID
        in_port = msg.match['in_port'] # 匹配输入端口'in_port'字段

        # 将交换机7端口传入的消息存入self.packet_out_msg中，作为Packet-Out的目的地
        if in_port == 7:
            self.packet_out_msg = msg
        #if msg is not None:
        #    print('mydebug: packet_out_msg:', self.packet_out_msg.data)

        pkt = packet.Packet(msg.data) # 利用消息的数据创建数据包
        eth_header = pkt.get_protocols(ethernet.ethernet)[0] # 获取数据包的以太网信息

        # 忽略LLDP包和IPv6包
        if eth_header.ethertype == ether_types.ETH_TYPE_LLDP or eth_header.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet and ipv6 packet
            return
        dst = eth_header.dst # 获取源MAC地址
        src = eth_header.src # 获取目的MAC地址

        #arp_header = pkt.get_protocol(arp.arp) # 获取数据包的ARP协议信息
        #print('mydebug: arp_header:', arp_header)
        ipv4_header = pkt.get_protocol(ipv4.ipv4) # 获取数据包的IPv4协议信息
        #print('mydebug: ipv4_header:', ipv4_header)
        udp_header = pkt.get_protocol(udp.udp) # 获取数据包的UDP协议信息
        #print('mydebug: udp_header:', ipv4_header)

        # 忽略交换机之间的端口，从指定消息中解析和保存所需的各项信息
        if self.port_features and (self.port_features.get(dpid).get(in_port)[2] != 0):
            '''
            # 如果数据包有ARP协议，记录其源IP与输入端口的映射关系
            if arp_header:
                for item in arp_header:
                    key = (dpid, in_port) # 键为DPID和输入端口
                    value = item.src_ip
                    self.ipv4_to_port.setdefault(key, value)
                    print('mydebug: self.ipv4_to_port:', self.ipv4_to_port)
            '''

            # 如果数据包有IPv4和UDP协议，且UDP目的端口号为12345，记录其源IP地址与输入端口的映射关系，从中解析和保存所需的各项信息
            if ipv4_header and udp_header and (udp_header.dst_port == 12345):
                #print('mydebug: udp_header.dst_port:', udp_header.dst_port)
                self._parse_ipv4_and_udp(dpid, in_port, msg.data)
                #print('mydebug: self.ipv4_to_port:', self.ipv4_to_port)
                #print('mydebug: self.port_osd_info:', self.port_osd_info)
                self._save_ipv4_osd_info(self.port_osd_info, self.ipv4_to_port, self.ipv4_osd_info)

        #dpid = format(datapath.id, "d").zfill(16) # 将DPID并填充到16位
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # 记录MAC地址与端口的映射关系
        # 初始化self.mac_to_port[dpid]
        if dpid not in self.mac_to_port.keys():
            self.mac_to_port.setdefault(dpid, {})
        # 初始化self.mac_to_port[dpid][src]
        if src not in self.mac_to_port[dpid].keys():
            self.mac_to_port[dpid].setdefault(src, None)
        if self.mac_to_port[dpid][src] != in_port:
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
        #print('mydebug: self.mac_to_port:', self.mac_to_port)

        # 以下内容用不到

        '''
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

         install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
           # verify if we have a valid buffer_id, if yes avoid to send both
           # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        '''

    # 发送请求消息到交换机以获取一些统计信息
    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 端口描述信息
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        # 端口统计信息：包含每个端口收发的数据包数量、字节数、丢包数等等
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        # 流表统计信息：包含每个流表项的标识信息（源和目的IP地址、协议、MAC地址，输入输出端口等）、计数器、超时、指令、优先级以及持续时间等
        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)

    # 通过ofp_event.EventOFPPortDescStatsReply事件触发接收端口描述信息并存入self.port_features
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        # 预设一些配置和状态字段参数用于判断
        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        stat_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}
        # 从Port Desc Stats Reply消息中收集端口信息
        for p in ev.msg.body:
            '''
            self.logger.info('port_no=%d hw_addr=%s name=%s config=0x%08x '
                             'state=0x%08x curr=0x%08x advertised=0x%08x '
                             'supported=0x%08x peer=0x%08x curr_speed=%d '
                             'max_speed=%d',
                             p.port_no, p.hw_addr,
                             p.name, p.config,
                             p.state, p.curr, p.advertised,
                             p.supported, p.peer, p.curr_speed,
                             p.max_speed)
            '''

            config = 'up'
            if p.config in config_dict:
                config = config_dict[p.config]

            stat = ''
            if p.state in stat_dict:
                stat = stat_dict[p.state]

            port_feature = (config, stat, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    # 接收端口描述信息并将部分数据存入self.port_stats；计算剩余带宽，存入self.free_bandwidth和self.ipv4_osd_info
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body= ev.msg.body
        dpid = ev.msg.datapath.id

        # 从Port Stats Reply消息中收集端口信息
        for p in ev.msg.body:
            '''
            self.logger.info('port_no=%d rx_packets=%d tx_packets=%d '
                             'rx_bytes=%d tx_bytes=%d rx_dropped=%d '
                             'tx_dropped=%d rx_errors=%d tx_errors=%d '
                             'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                             'collisions=%d duration_sec=%d duration_nsec=%d',
                             p.port_no, p.rx_packets, p.tx_packets,
                             p.rx_bytes, p.tx_bytes, p.rx_dropped,
                             p.tx_dropped, p.rx_errors, p.tx_errors,
                             p.rx_frame_err, p.rx_over_err,
                             p.rx_crc_err, p.collisions,
                             p.duration_sec, p.duration_nsec)
            '''
            if p.port_no != ofproto_v1_3.OFPP_LOCAL: # 忽略交换机内部端口号0xfffffffe（4294967294）
                key = (dpid, p.port_no) # 键为DPID和输入端口
                value = (p.tx_bytes, p.rx_bytes, p.rx_errors,
                         p.duration_sec, p.duration_nsec)
                # 值为发送、接收的字节数，接收的错误数，流表项在交换机中的存在时间（秒、纳秒）
                self._save_stats(self.port_stats, key, value, 5) # 将value存入self.port_stats，每个键只保留最新的5个值

                # 获取端口速度
                p_bytes = 0 # 初始化端口上次收发字节数
                n_bytes = 0 # 初始化端口本次收发字节数
                period = setting.MONITOR_PERIOD # 初始化时间间隔
                port_stat = self.port_stats[key]
                if len(port_stat) > 1: # 至少需要两条记录才能计算速度
                    p_bytes = port_stat[-2][0] + port_stat[-2][1] # 端口上次收发字节数
                    period = self._get_period(port_stat[-1][3], port_stat[-1][4],
                                              port_stat[-2][3], port_stat[-2][4])
                    # 获取上次端口状态和本次端口状态的时间间隔
                n_bytes = port_stat[-1][0] + port_stat[-1][1] # 端口本次收发字节数
                speed = self._get_speed(n_bytes, p_bytes, period)
                #self._save_stats(self.port_speed, key, speed, 5) # 将speed存入self.port_speed，每个键只保留最新的5个值
                self._save_free_bw(dpid, p.port_no, speed)
                self._save_ip_free_bw(self.port_free_bw, self.ipv4_to_port, self.ipv4_osd_info)

    # 用于向字典_dict中保存数据，键为key，值为列表，向值列表中追加value, 并限制列表长度为length，长度溢出时弹出最早的元素
    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        while len(_dict[key]) > length:
            _dict[key].pop(0)

    # 计算当前的总秒数和上一次的总秒数，得到并返回两者之差作为时间间隔
    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_sec(n_sec, n_nsec) - self._get_sec(p_sec, p_nsec)

    # 通过秒数和纳秒数计算并返回总秒数
    def _get_sec(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    # 利用本次和上次字节数之差以及对应的时间间隔计算速度，单位为B/s
    def _get_speed(self, now_bytes, pre_bytes, period):
        if period: # 除数不能为0
            return (now_bytes - pre_bytes) / period
        else:
            return 0

    # 计算并保存端口剩余带宽
    def _save_free_bw(self, dpid, port_no, speed):
        port_feature = self.port_features.get(dpid).get(port_no)
        if port_feature:
            if port_feature[2] != 0:
                bw = port_feature[2]
                free_bw = self._get_free_bw(bw, speed)
                key = (dpid, port_no)
                self.port_free_bw.setdefault(key, None)
                self.port_free_bw[key] = free_bw
        else:
            self.logger.info('Fail in getting port feature')

    # 通过接口带宽（Kbps）和传输速度（B/s）计算并返回剩余带宽，单位为Kbps
    def _get_free_bw(self, bw, speed):
        return max(bw - speed /1000 * 8, 0) # 计算结果不能为负

    # 通过端口剩余带宽以及IPv4地址与端口的的映射关系，将剩余带宽存入主机信息中
    def _save_ip_free_bw(self, port_free_bw, ipv4_to_port, ipv4_osd_info):
        if_dict_port_free_bw = isinstance(port_free_bw, dict)
        if not if_dict_port_free_bw:
            TypeError('mydebug: Type of port_free_bw is not dict.')
        if_dict_ipv4_to_port = isinstance(ipv4_to_port, dict)
        if not if_dict_ipv4_to_port:
            TypeError('mydebug: Type of ipv4_to_port is not dict.')
        if_dict_ipv4_osd_info = isinstance(ipv4_osd_info, dict)
        if not if_dict_ipv4_osd_info:
            TypeError('mydebug: Type of ipv4_osd_info is not dict.')

        if if_dict_port_free_bw and if_dict_ipv4_to_port and if_dict_ipv4_osd_info:
            for key in port_free_bw.keys():
                if key in ipv4_to_port:
                    if ipv4_to_port[key] not in ipv4_osd_info.keys():
                        ipv4_osd_info.setdefault(ipv4_to_port[key], {'bw': 0, 'class': None, 'cpu': 0, 'mem': 0, 'io': 0})
                    ipv4_osd_info[ipv4_to_port[key]]['bw'] = port_free_bw[key]

    # 输入DPID、端口号以及UDP消息的数据部分，解析出所需据，存入self.ipv4_to_port和self.osd_info中
    def _parse_ipv4_and_udp(self, dpid, port, msg_data):
        eth_data = ethernet.ethernet.parser(msg_data) # 解析以太网数据
        #print('mydebug: ethernet.ethernet.parser(msg_data):', eth_data)
        ip_data = ipv4.ipv4.parser(eth_data[2]) # 解析IPv4数据
        #print('mydebug: ipv4.ipv4.parser(eth_data):', ip_data)
        udp_data = udp.udp.parser(ip_data[2]) # 解析UDP数据
        #print('mydebug: udp.udp.parser(ip_data):', udp_data)

        key = (dpid, port) # 键为DPID和输入端口
        self.ipv4_to_port[key] = ip_data[0].src # 值为源IPv4地址
        self.port_osd_info[key] = udp_data[2] # 值为UDP数据

    # 通过端口对应主机的OSD信息以及IPv4地址与端口的的映射关系，写入IPv4地址对应主机的OSD信息中
    def _save_ipv4_osd_info(self, port_osd_info, ipv4_to_port, ipv4_osd_info):
        for key in ipv4_to_port.keys():
            if key in port_osd_info:
                info = eval(port_osd_info[key])
                if ipv4_to_port[key] not in ipv4_osd_info.keys():
                    ipv4_osd_info.setdefault(ipv4_to_port[key], {'bw': 0, 'class': None, 'cpu': 0, 'mem': 0, 'io': 0})
                ipv4_osd_info[ipv4_to_port[key]]['class'] = info[0]
                ipv4_osd_info[ipv4_to_port[key]]['cpu'] = info[1]
                ipv4_osd_info[ipv4_to_port[key]]['mem'] = info[2]
                ipv4_osd_info[ipv4_to_port[key]]['io'] = info[3]

    # 指定秒数来实现time.sleep()，并以指定的间隔输出倒计时
    def _sleep_with_countdown(self, sec = 1, period = 0.1):
        i = float(sec)
        while i > 0:
            print('\rmydebug: It\'s the final coundown: ' + str(round(i, 1)) + 's', end='')
            i -= period
            time.sleep(period)
        print('\rmydebug: It\'s the final coundown: ' + str(round(0.0, 1)) + 's\n')
