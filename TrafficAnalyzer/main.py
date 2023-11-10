import yaml
from multiprocessing import Process
from kafka import KafkaProducer, KafkaConsumer

from abnomal_traffic.ddos import detect

# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

def start_traffic(args_config):
    # 创建进程池
    processes = []
    # ddos 
    # 消息队列设置
    ddos_consumer = KafkaConsumer(args_config['mq']['traffic_topic'],
                         group_id=args_config['mq']['ddos_group_id'],
                         bootstrap_servers=args_config['mq']['bootstrap_servers']
                         )
    ddos_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    # 创建对象
    ddos_detector = detect.DDoS_Detector(traffic_consumer=ddos_consumer, 
                             event_producer=ddos_producer, 
                             topic=args_config['mq']['event_topic'],
                             model_path=args_config['abnormal_traffic']['ddos']['model'],
                             encoder_path=args_config['abnormal_traffic']['ddos']['encoder']
                             )
    # ddos_detector.detect()
    processes.append(Process(target=ddos_detector.detect, args=(1000,)))

    # 开始进程
    for p in processes:
        p.start()


if __name__ == '__main__':
    # 获取配置
    args_config = init_config('/home/dachilles/Workspace/NSSA_system/NSSA_Traffic/TrafficAnalyzer/config.yaml')
    # 开始流量检测
    start_traffic(args_config)