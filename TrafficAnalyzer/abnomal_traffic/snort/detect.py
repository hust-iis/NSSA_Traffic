import json
import os
import pickle

import yaml
from kafka import KafkaProducer

from message import AbnormalEventMSG, MSG_TYPE_TRAFFIC
from abnomal_traffic.msg_models.models import AbnormalTraffic, FLOW_TYPE_PORTSCAN, FLOW_TYPE_SQLINJECT, FLOW_TYPE_XMLINJECT


class Snort_Detector:

    def __init__(self, event_producer, topic,password, interface, snortpath, luapath) -> None:
        # 消息队列
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic

        #snort portscan 设置
        self.password = password
        self.sudo_cmd_flag = False
        self.interface = interface
        self.luapath = luapath
        self.snortpath = snortpath
        with open('./abnomal_traffic/snort/alert_json.txt', 'r') as file:
            content = file.read()
            lines = content.split('\n')
            line_count = len(lines)
            if line_count > 5000:
                # 执行删除操作，清空文件内容
                with open('./abnomal_traffic/snort/alert_json.txt', 'w') as file:
                    pass
                self.old_lines = 0
            else:
                self.old_lines = line_count

    def detect(self):
        flag = True
        print("snort")
        try:
            while flag:
                self.predict()
        except KeyboardInterrupt:
            pass

    def sudo_cmd(self):
        if self.sudo_cmd_flag == False:
            print('gnome-terminal -x bash -c \' echo {} | sudo -S {} -c {} -A alert_json -i {} -s 65535 -k none -l ./ ;exec bash \' '.format(
                self.password, self.snortpath, self.luapath, self.interface))
            os.system('gnome-terminal -x bash -c \' echo {} | sudo -S {} -c {} -A alert_json -i {} -s 65535 -k none -l ./abnomal_traffic/snort ;exec bash \' '.format(
                self.password, self.snortpath, self.luapath, self.interface))
            os.system('echo {} | sudo -S chmod 777 ./abnomal_traffic/snort/alert_json.txt'.format(self.password))
        self.sudo_cmd_flag = True

    def predict(self):
        self.sudo_cmd()

        # print("port_scan_openfile")
        # print(length)
        with open('./abnomal_traffic/snort/alert_json.txt', 'r+') as file:
            for i in range(self.old_lines):
                file.readline()
                # print("oldline")
            while True:
                line = file.readline().strip()
                if not line:
                    break
                self.old_lines += 1
                print(line)
                json_data = json.loads(line)
                if "Port Scan" in json_data["msg"]:
                    event = AbnormalTraffic(
                        type=FLOW_TYPE_PORTSCAN,
                        time=json_data["timestamp"],
                        src=json_data["src_ap"],
                        dst=json_data["dst_ap"],
                        detail=json_data["timestamp"])
                elif "SQL Inject" in json_data["msg"]:
                    event = AbnormalTraffic(
                        type=FLOW_TYPE_SQLINJECT,
                        time=json_data["timestamp"],
                        src=json_data["src_ap"],
                        dst=json_data["dst_ap"],
                        detail=json_data["timestamp"])
                elif "XML Inject" in json_data["msg"]:
                    event = AbnormalTraffic(
                        type=FLOW_TYPE_XMLINJECT,
                        time=json_data["timestamp"],
                        src=json_data["src_ap"],
                        dst=json_data["dst_ap"],
                        detail=json_data["timestamp"])
                message = pickle.dumps(AbnormalEventMSG(type=MSG_TYPE_TRAFFIC, data=event))
                self.MQ_Event.send(self.MQ_Event_Topic, message)

# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config


if __name__ == '__main__':
    args_config = init_config('./config.yaml')
    # snort
    snort_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    snort_detector = Snort_Detector(event_producer=snort_producer,
                                        topic=args_config['mq']['port_scan_id'],
                                        password=args_config['abnormal_traffic']['snort']['password'],
                                        luapath=args_config['abnormal_traffic']['snort']['luapath'],
                                        snortpath=args_config['abnormal_traffic']['snort']['snortpath'],
                                        interface=args_config['abnormal_traffic']['snort']['interface'])
    snort_detector.detect()
