import yaml
import pickle
import pyshark
from kafka import KafkaProducer

# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

def main():
    # 获取配置
    args_config = init_config('../config.yaml')
    # 设置消息队列
    producer = KafkaProducer(bootstrap_servers=args_config['mq']['server'])
    topic = args_config['mq']['traffic_topic']
    # 设置监听器
    capture = pyshark.LiveCapture(
        interface=args_config['traffic_gathering']['interface'],
        bpf_filter=args_config['traffic_gathering']['capture_filter']
    )
    capture.sniff_continuously(packet_count=None)
    # 获取流量包
    for pkt in capture:
        message = pickle.dumps(pkt)
        producer.send(topic, message)

if __name__ == '__main__':
    main()
