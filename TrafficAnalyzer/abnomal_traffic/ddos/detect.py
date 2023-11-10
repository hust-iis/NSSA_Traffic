import copy
import pickle
import time
from datetime import datetime

import pandas as pd
from sklearn.preprocessing import LabelEncoder

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))
from msg_models.models import AbnormalFlowModel, FLOW_TYPE_DDOS

class DDoS_Detector:
    # 初始化
    def __init__(self, traffic_consumer, event_producer, topic, model_path, encoder_path):
        # 消息队列相关
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic
        # 模型
        self.cordon = 0.8
        self.model = pickle.load(open(model_path, 'rb'))
        self.encoder = pickle.load(open(encoder_path, 'rb'))
        self.features = ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP',
                         'Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']
        # 设置
        self.allowed = []

    # 分析
    def analysis(self, pkt_list, suspicious_percent):
        # 数据处理
        data = _pkts_transformer(self.features, self.allowed, pkt_list)
        print(data)
        data = _label_encoding(data, self.encoder)
        print(data)
        # 选取数据属性
        X = data[self.features]
        # 对数据进行预测
        predictions = self.model.predict(X)
        # 统计
        hostile = safe = 0
        for check in predictions:
            if check == 1:
                hostile += 1
            else:
                safe += 1
        # 返回
        return hostile / (hostile + safe) > suspicious_percent

    # FIXME: 告警
    def alert(self, pkt_list):
        # 统计目标IP
        dst_ip_dict = dict()
        for pkt in pkt_list:
            # 检查IPv4 or IPv6
            ip_layer = _pkt_ip_layer(pkt)
            # 更新IP信息
            if ip_layer == 'ip':
                ip = pkt.ip
            elif ip_layer == 'ipv6':
                ip = pkt.ipv6
            # 更新字典
            if ip.addr in dst_ip_dict:
                dst_ip_dict[ip.addr].append(pkt)
            else:
                dst_ip_dict[ip.addr] = [pkt]
        # 目标IP超过一定值则认为是真正目标
        for ip, pkts in dst_ip_dict.items():
            if len(pkts) > 0.3*len(pkt_list):
                event = AbnormalFlowModel(
                    type=FLOW_TYPE_DDOS,
                    time=datetime.now(),
                    src="",
                    dst=ip,
                    detail=copy.deepcopy(pkts))
                message = pickle.dumps(event)
                self.MQ_Event.send(self.MQ_Event_Topic, message)
        

    # 检测
    def detect(self, pkt_lens=100, threads=10):
        pkt_list = []
        # 取出一条消息
        for msg in self.MQ_Traffic:
            # list塞满了，将其传入线程池进行预测处理
            if len(pkt_list) >= pkt_lens:
                ########################### TODO 多线程化 ######################
                # 检测+报警
                if self.analysis(copy.deepcopy(pkt_list), self.cordon):
                    self.alert(pkt_list)
                ##############################################################    
                # 清空列表
                pkt_list.clear()
            # 反序列化
            pkg = pickle.loads(msg.value)
            # 添加到list
            pkt_list.append(pkg)


""" 以下是功能函数 """

# 判断IPv6
def _pkt_ip_layer(pkt):
    for layer in pkt.layers:
        if layer._layer_name in ['ip', 'ipv6']:
            return layer._layer_name


# 数据获取
def _pkts_transformer(features, allowed_ip, pkt_list):
    df = pd.DataFrame(columns=features)
    first_timestamp = float(pkt_list[0].sniff_timestamp)
    for i, pkt in enumerate(pkt_list):
        try:
            ip = None
            ipcat = 1
            transport_layer = 'None'
            # ARP协议没有IP信息
            if pkt.highest_layer != 'ARP':
                # 检查IPv4 or IPv6
                ip_layer = _pkt_ip_layer(pkt)
                # 更新IP信息
                if ip_layer == 'ip':
                    ip = pkt.ip
                elif ip_layer == 'ipv6':
                    ip = pkt.ipv6
                # 允许srcIP=0, 不允许srcIP=1
                if ip.src not in allowed_ip:
                    ipcat = 1
                else:
                    ipcat = 0
                # 更新传输层协议信息
                if pkt.transport_layer != None:
                    transport_layer = pkt.transport_layer
                # 更新时间
                if i == 0:
                    pkts_time = 0
                else:
                    pkts_time = i / (float(pkt.sniff_timestamp) - first_timestamp)
                # 将
                try:
                    df.loc[len(df.index)] = [pkt.highest_layer, transport_layer, ipcat, ip.dst,
                                             pkt[pkt.transport_layer].srcport, pkt[pkt.transport_layer].dstport,
                                             pkt.length, pkts_time]
                except AttributeError:
                    df.loc[len(df.index)] = [pkt.highest_layer, transport_layer, ipcat, ip.dst,
                                             0, 0, pkt.length, pkts_time]
            else:
                # srcIP
                if pkt.arp.src_proto_ipv4 not in allowed_ip:
                    ipcat = 1
                else:
                    ipcat = 0
                # 其他信息
                arp = pkt.arp
                # 更新时间
                if i == 0:
                    pkts_time = 0
                else:
                    pkts_time = i / (float(pkt.sniff_timestamp) - first_timestamp)
                df.loc[len(df.index)] = [pkt.highest_layer, transport_layer, ipcat, arp.dst_proto_ipv4,
                                         0, 0, pkt.length, pkts_time]
        except (UnboundLocalError, AttributeError) as e:
            pass
    return df

# 数据编码
def _label_encoding(data, encoder):
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
    # print(columnsToEncode)
    # labelEncoder = LabelEncoder()
    labelEncoder = encoder
    for feature in columnsToEncode:
        try:
            data[feature] = labelEncoder.fit_transform(data[feature])
        except:
            print('[error feature]: ' + feature)
    return data
