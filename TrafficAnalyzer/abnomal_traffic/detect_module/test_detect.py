import pickle

import pyshark
import yaml
import threading
from queue import Queue

from kafka import KafkaProducer

from Trojan.detector import Trojan_Detector
from Virus.detector import Virus_Detector
from Worm.detector import Worm_Detector

# 初始化配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

# 检测test目录
def detect():
    # 初始化
    # 配置参数
    args_config = init_config('../../../config.yaml')

    # 事件队列
    threads = []
    event_queue = Queue(maxsize=200)

    # 为每一项检测创建一个线程

    # # Trojan
    # trojan_detector = Trojan_Detector(test_path=args_config['testpath'],
    #                                   model_path=args_config['Trojan']['model_path'],
    #                                   event_queue=event_queue)
    # thread_trojan = threading.Thread(target=trojan_detector.detect)
    # threads.append(thread_trojan)

    # Worm
    worm_detector = Worm_Detector(test_path=args_config['testpath'],
                                      model_path=args_config['Worm']['model_path'],
                                      event_queue=event_queue)
    thread_worm = threading.Thread(target=worm_detector.detect)
    threads.append(thread_worm)

    # # Virus
    # virus_detector = Virus_Detector(test_path=args_config['testpath'],
    #                                   model_path=args_config['Virus']['model_path'],
    #                                   event_queue=event_queue)
    # thread_virus = threading.Thread(target=virus_detector.detect)
    # threads.append(thread_virus)

    # 启动线程
    for th in threads:
        th.start()

# 发送检测结果到事件队列
def send_result(message):
    # 获取配置
    args_config = init_config('../config.yaml')
    # 设置消息队列
    producer = KafkaProducer(bootstrap_servers=args_config['mq']['server'])
    topic = args_config['mq']['event_topic']

    # 发送检测结果
    message = pickle.dumps(message)
    producer.send(topic, message)

if __name__ == '__main__':
    detect()
    # send_result(message)



