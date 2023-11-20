import copy
import os
import pickle
from datetime import datetime

import numpy
import joblib
from sklearn.neural_network import MLPClassifier

from abnomal_traffic.msg_models.models import AbnormalFlowModel, FLOW_TYPE_WEBSHELL


class Webshell_Detector:
    # 初始化
    def __init__(self, traffic_consumer, event_producer, topic,
                 model_path, count_vectorizer_path, transformer_path):
        # 消息队列相关
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic
        # 机器学习模型
        self.model_path = model_path
        self.count_vectorizer_path = count_vectorizer_path
        self.transformer_path = transformer_path
        # 模型
        self.model = None
        self.count_vectorizer = None
        self.transformer = None
        self.load_model()

    # 加载模型
    def load_model(self):
        # 加载模型
        if os.path.isfile(self.model_path):
            clf = joblib.load(self.model_path)
        else:
            clf = MLPClassifier(solver='lbfgs', alpha=1e-5, learning_rate='adaptive',
                                hidden_layer_sizes=(5, 2), random_state=1, activation='relu',
                                verbose=False, tol=1e-4, shuffle=True, learning_rate_init=0.001)
        self.model = clf
        # 加载CountVectorizer
        self.count_vectorizer = joblib.load(self.count_vectorizer_path)
        # 加载transformer
        self.transformer = joblib.load(self.transformer_path)

    # 检测
    def detect(self, threads=10):
        for msg in self.MQ_Traffic:
            # 反序列化
            pkt = pickle.loads(msg.value)
            # 解析
            if self.analysis(pkt):
                self.alert(pkt)

    # 分析
    def analysis(self, pkt):
        data_string = ''
        # 有data段的http包
        if hasattr(pkt, 'http'):
            if hasattr(pkt.http, 'data'):
                # 提取pkt中data信息
                data = pkt.http.data
                data_byte_str = bytes.fromhex(data)
                data_string = data_byte_str.decode('utf-8')
        # 文件传输的包
        if hasattr(pkt, 'mime_multipart'):
            if hasattr(pkt.mime_multipart, 'data'):
                # 提取pkt中data信息
                data = pkt.mime_multipart.data
                data_byte_str = bytes.fromhex(data)
                data_string = data_byte_str.decode('utf-8')
        # 没有data，不会是webshell包
        if len(data_string) == 0:
            return False
        # 特征转化提取
        x = [data_string]
        x = self.count_vectorizer.transform(x).toarray()
        x = self.transformer.transform(x).toarray()
        # 检测
        res_raw = self.model.predict_proba(x)
        return numpy.argmax(res_raw, axis=1)[0]

    # 告警
    def alert(self, pkt):
        # 创建消息
        event = AbnormalFlowModel(
            type=FLOW_TYPE_WEBSHELL,
            time=datetime.now(),
            src=pkt.ip.src,
            dst=pkt.ip.dst,
            detail=copy.deepcopy(pkt)
        )
        # push消息
        message = pickle.dumps(event)
        self.MQ_Event.send(self.MQ_Event_Topic, message)
