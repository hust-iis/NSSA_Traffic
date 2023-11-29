import copy
import os
import re
from datetime import datetime

import cv2
import pickle
import numpy as np
import pandas as pd
import urllib.parse

# import tensorflow.compat.v1 as tf
# tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)

from TrafficAnalyzer.message import AbnormalEventMSG, MSG_TYPE_TRAFFIC
from abnomal_traffic.msg_models.models import AbnormalTraffic, FLOW_TYPE_XSS


class XSS_Detector:
    def __init__(self, traffic_consumer, event_producer, topic, model_path):
        # 消息队列相关
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic
        # 机器学习模型
        self.model_path = model_path

    # 告警
    def alert(self, pkt):
        # 创建消息
        event = AbnormalTraffic(
            type=FLOW_TYPE_XSS,
            time=datetime.now(),
            src=pkt.ip.src,
            dst=pkt.ip.dst,
            detail=copy.deepcopy(pkt)
        )
        # push消息
        message = pickle.dumps(AbnormalEventMSG(type=MSG_TYPE_TRAFFIC, data=event))
        self.MQ_Event.send(self.MQ_Event_Topic, message)
        return

    def check_xss(self, flow_data, info, detail):
        flow_data = str(flow_data)
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
        os.environ['CUDA_VISIBLE_DEVICES'] = '/gpu:0'
        data = [{"Sentence": flow_data}]
        df = pd.DataFrame(data)
        # Get Sentences data from data frame
        sentences = df['Sentence'].values
        # Convert to ASCII
        # send each sentence to be converted to ASCII
        arr = np.zeros((len(sentences), 100, 100))
        for i in range(len(sentences)):
            image = convert_to_ascii(sentences[i])
            x = np.asarray(image, dtype='float')
            image = cv2.resize(x, dsize=(100, 100), interpolation=cv2.INTER_CUBIC)
            image /= 128
            arr[i] = image
        print("Input data shape : ", arr.shape)
        # Reshape data for input to CNN
        data = arr.reshape(arr.shape[0], 100, 100, 1)
        data.shape
        # y=df['Label'].values
        fr = open(self.model_path, "rb")
        model = pickle.load(fr)
        # predict for test set
        testX = data
        # testY = y
        pred = model.predict(testX)
        for i in range(len(pred)):
            if pred[i] > 0.5:
                pred[i] = 1
            elif pred[i] <= 0.5:
                pred[i] = 0
        for evpred in pred:
            if evpred[0]:
                return True
        return False

    # 分析
    def analysis(self, pkt):
        # http报文检测
        if hasattr(pkt, 'http'):
            http = pkt.http
            # 检测报文的URI字段是否存在XSS攻击
            if hasattr(http, 'request_uri'):
                # url解码
                http_uri = urllib.parse.unquote(http.request_uri)
                # 提取出XSS数据
                data = extract_data(http_uri)
                # 检测
                return self.check_xss(data, 'uri', http.request_full_uri)

            # 检测报文的Referer字段是否存在XSS攻击
            if hasattr(http, 'referer'):
                # url解码
                http_referer = urllib.parse.unquote(http.referer)
                # 提取出XSS数据
                data = extract_data(http_referer)
                # 检测
                return self.check_xss(data, 'referer', http_referer)

            # 检测报文的cookie字段
            if hasattr(http, 'cookie'):
                # 获取cookie
                http_cookie = http.cookie
                # 提取出XSS数据
                data = extract_data(http_cookie)
                # 检测
                return self.check_xss(data, 'cookie', http_cookie)

            # 检测报文的user_agent字段
            if hasattr(http, 'user_agent'):
                # 解析
                http_useragent = http.user_agent
                # 提取出XSS数据
                data = extract_data(http_useragent)
                # 检测
                return self.check_xss(data, 'user-agent', http_useragent)

        # 检测post参数输入
        if hasattr(pkt, 'urlencoded-form'):
            # 获取post参数
            post_attr = getattr(pkt, 'urlencoded-form')
            # 将对象转换为字符串类型
            post_str = str(post_attr)
            # 去掉控制字符
            post_str = re.sub(r'\x1b\[0m\x1b\[1m', '', post_str)

            values = []
            for line in post_str.split('\n'):
                if 'Value:' in line:
                    value = line.strip().split(':')[-1].strip()
                    values.append(value)

            # 检测post提交的每个参数字段
            for value in values:
                print(f"post params data: {value}")
                info = 'post params'
                if self.check_xss(value, info, value):
                    return True


    # 检测
    def detect(self, threads=10):
        for msg in self.MQ_Traffic:
            # 反序列化
            pkt = pickle.loads(msg.value)
            # 解析
            if self.analysis(pkt):
                self.alert(pkt)


#提取出有<>符号的部分（不提取出来原本的机器学习无法正确检测），因为大部分xss攻击都会有<>，现在不考虑除此之外的攻击
def extract_data(origindata):
    match = re.search("<.*>", origindata)
    data = ''
    if match:
        data = match.group(0)
    return data


def convert_to_ascii(sentence):
    sentence_ascii = []
    sentence = str(sentence)
    for i in sentence:

        """Some characters have values very big e.d 8221 adn some are chinese letters
        I am removing letters having values greater than 8222 and for rest greater 
        than 128 and smaller than 8222 assigning them values so they can easily be normalized"""

        if (ord(i) < 8222):  # ” has ASCII of 8221

            if (ord(i) == 8217):  # ’  :  8217
                sentence_ascii.append(134)

            if (ord(i) == 8221):  # ”  :  8221
                sentence_ascii.append(129)

            if (ord(i) == 8220):  # “  :  8220
                sentence_ascii.append(130)

            if (ord(i) == 8216):  # ‘  :  8216
                sentence_ascii.append(131)

            if (ord(i) == 8217):  # ’  :  8217
                sentence_ascii.append(132)

            if (ord(i) == 8211):  # –  :  8211
                sentence_ascii.append(133)

            """
            If values less than 128 store them else discard them
            """
            if (ord(i) <= 128):
                sentence_ascii.append(ord(i))

            else:
                pass

    zer = np.zeros((10000))

    for i in range(len(sentence_ascii)):
        zer[i] = sentence_ascii[i]

    zer.shape = (100, 100)

    return zer