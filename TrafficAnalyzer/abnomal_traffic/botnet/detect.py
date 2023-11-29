import copy
from datetime import datetime
import pickle
import socket
import struct

import numpy

from message import AbnormalEventMSG, MSG_TYPE_TRAFFIC
from abnomal_traffic.msg_models.models import AbnormalTraffic, FLOW_TYPE_BOTNET


class Botnet_Detector:
    # 初始化
    def __init__(self, traffic_consumer, event_producer, topic, model_path):
        # 消息队列相关
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic
        # 模型
        self.model = pickle.load(open(model_path, 'rb'))
        self.features = []
        self.protocolDictionary = {'arp': 5, 'unas': 13, 'udp': 1, 'rtcp': 7, 'pim': 3, 'udt': 11, 'esp': 12,
                                   'tcp': 0, 'rarp': 14, 'ipv6-icmp': 9, 'rtp': 2, 'ipv6': 10, 'ipx/spx': 6, 'icmp': 4,
                                   'igmp': 8}
        self.stateDictionary = {'': 1, 'FSR_SA': 30}
        # 其他设置

    # 分析
    def analysis(self, pkt):
        # 定义一条待检测流量特征
        data = []
        # 特征解析
        duration = pkt.frame_info.time_delta_displayed
        protocol = pkt.transport_layer.lower()  # proto

        src_ip = pkt.ip.src
        src_ip = socket.inet_aton(src_ip)
        src_ip = struct.unpack("!L", src_ip)[0]
        src_port = pkt[protocol].srcport  # src_port

        dst_ip = pkt.ip.dst  # dst_addr
        dst_ip = socket.inet_aton(dst_ip)
        dst_ip = struct.unpack("!L", dst_ip)[0]
        dst_port = pkt[protocol].dstport  # dst_port

        state = 'FSR_SA'
        totP = pkt.tcp.seq + pkt.tcp.ack  # tot_pkts
        totB = pkt.length  # tot_bytes

        if (src_port == '') or (dst_port == ''):
            return False
        # 填充特征
        data = numpy.array([float(duration), self.protocolDictionary[protocol],
                int(src_port), int(dst_port), src_ip, dst_ip,
                int(totP), int(totB), self.stateDictionary[state]])
        # 预测
        return self.model.predict(data.reshape(1, -1))

    # 告警
    def alert(self, pkt):
        # 创建消息
        event = AbnormalTraffic(
            type=FLOW_TYPE_BOTNET,
            time=datetime.now(),
            src=pkt.ip.src,
            dst=pkt.ip.dst,
            detail=copy.deepcopy(pkt)
        )
        # push消息
        message = pickle.dumps(AbnormalEventMSG(type=MSG_TYPE_TRAFFIC, data=event))
        self.MQ_Event.send(self.MQ_Event_Topic, message)

    # 检测
    def detect(self, threads=10):
        for msg in self.MQ_Traffic:
            # 反序列化
            pkt = pickle.loads(msg.value)
            # 解析
            if self.analysis(pkt):
                self.alert(pkt)
