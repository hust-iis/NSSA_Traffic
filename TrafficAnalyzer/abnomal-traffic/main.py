import time

import yaml
import pickle
import pyshark
from kafka import KafkaProducer
from msg_models import models

# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

def main():
    # 获取配置
    args_config = init_config('../../config.yaml')
    # 设置消息队列
    producer = KafkaProducer(bootstrap_servers=args_config['mq']['server'])
    topic = args_config['mq']['traffic_topic']
    msg = models.AbnormalFlowModel(0,time.localtime(),'192.168.0.1','192.168.0.2','test')
    message = pickle.dumps(msg)
    producer.send(topic, message)

if __name__ == '__main__':
    main()