import yaml
from multiprocessing import Process
from kafka import KafkaProducer, KafkaConsumer

from abnomal_traffic.botnet.detect import Botnet_Detector
from abnomal_traffic.ddos.detect import DDoS_Detector
from abnomal_traffic.virus.detect import Virus_Detector
from abnomal_traffic.worm.detect import Worm_Detector
from abnomal_traffic.trojan.detect import Trojan_Detector


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
    ddos_detector = DDoS_Detector(traffic_consumer=ddos_consumer,
                                  event_producer=ddos_producer,
                                  topic=args_config['mq']['event_topic'],
                                  model_path=args_config['abnormal_traffic']['ddos']['model'],
                                  encoder_path=args_config['abnormal_traffic']['ddos']['encoder']
                                  )
    # ddos_detector.detect()
    processes.append(Process(target=ddos_detector.detect, args=(1000,)))

    # botnet
    # 消息队列设置
    botnet_consumer = KafkaConsumer(args_config['mq']['traffic_topic'],
                                    group_id=args_config['mq']['botnet_group_id'],
                                    bootstrap_servers=args_config['mq']['bootstrap_servers']
                                    )
    botnet_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    # 创建对象
    botnet_detector = Botnet_Detector(traffic_consumer=botnet_consumer,
                                      event_producer=botnet_producer,
                                      topic=args_config['mq']['event_topic'],
                                      model_path=args_config['abnormal_traffic']['botnet']['model']
                                      )
    # botnet_detector.detect()
    processes.append(Process(target=botnet_detector.detect, args=()))

    # trojan
    # 消息队列设置
    trojan_consumer = KafkaConsumer(args_config['mq']['traffic_topic'],
                                    group_id=args_config['mq']['trojan_group_id'],
                                    bootstrap_servers=args_config['mq']['bootstrap_servers']
                                    )
    trojan_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    # 创建对象
    trojan_detector = Trojan_Detector(traffic_consumer=trojan_consumer,
                                             event_producer=trojan_producer,
                                             topic=args_config['mq']['event_topic'],
                                             model_path=args_config['abnormal_traffic']['trojan']['model']
                                             )
    trojan_detector.detect()
    processes.append(Process(target=trojan_detector.detect))

    # virus
    # 消息队列设置
    virus_consumer = KafkaConsumer(args_config['mq']['traffic_topic'],
                                   group_id=args_config['mq']['virus_group_id'],
                                   bootstrap_servers=args_config['mq']['bootstrap_servers']
                                   )
    virus_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    # 创建对象
    virus_detector = Virus_Detector(traffic_consumer=virus_consumer,
                                           event_producer=virus_producer,
                                           topic=args_config['mq']['event_topic'],
                                           model_path=args_config['abnormal_traffic']['virus']['model']
                                           )
    virus_detector.detect()
    # processes.append(Process(target=virus_detector.detect))

    # worm
    # 消息队列设置
    worm_consumer = KafkaConsumer(args_config['mq']['traffic_topic'],
                                  group_id=args_config['mq']['worm_group_id'],
                                  bootstrap_servers=args_config['mq']['bootstrap_servers']
                                  )
    worm_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    # 创建对象
    worm_detector = Worm_Detector(traffic_consumer=worm_consumer,
                                         event_producer=worm_producer,
                                         topic=args_config['mq']['event_topic'],
                                         model_path=args_config['abnormal_traffic']['worm']['model']
                                         )
    # worm_detector.detect()
    processes.append(Process(target=worm_detector.detect))

    # 开始进程
    for p in processes:
        p.start()
    # 等待所有子进程执行完毕
    for p in processes:
        p.join()


if __name__ == '__main__':
    # 获取配置
    args_config = init_config('./config.yaml')
    # 开始流量检测
    start_traffic(args_config)