import datetime
import json
import os
import pickle
import sys
from pathlib import Path

import yaml
from kafka import KafkaProducer

sys.path.append(str(Path(__file__).resolve().parents[1]))
from msg_models.models import AbnormalFlowModel, FLOW_TYPE_PORTSCAN


class Port_Scan_Detector:

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
        with open('alert_json.txt', 'r') as file:
            content = file.read()
            self.old_lines = len(content.split('\n'))

    def detect(self):
        flag = True
        print("port_scan")
        try:
            while flag:
                self.predict()
        except KeyboardInterrupt:
            pass

    def sudo_cmd(self):
        if self.sudo_cmd_flag == False:
            print('gnome-terminal -x bash -c \' echo {} | sudo -S {} -c {} -A alert_json -i {} -s 65535 -k none -l ./ ;exec bash \' '.format(
                self.password, self.snortpath, self.luapath, self.interface))
            os.system('gnome-terminal -x bash -c \' echo {} | sudo -S {} -c {} -A alert_json -i {} -s 65535 -k none -l ./ ;exec bash \' '.format(
                self.password, self.snortpath, self.luapath, self.interface))
            os.system('echo {} | sudo -S chmod 777 alert_json.txt'.format(123456))
        self.sudo_cmd_flag = True

    def predict(self):
        self.sudo_cmd()

        # print("port_scan_openfile")
        # print(length)
        with open('alert_json.txt', 'r') as file:
            for i in range(self.old_lines):
                file.readline()
                # print("oldline")
            while True:
                line = file.readline().strip()
                if not line:
                    break
                self.old_lines += 1
                # print(line)
                # if 'TCP SYN/Normal scan from host' in line:
                print(line)
                json_data = json.loads(line)
                # print(json_data["msg"])
                # print(json_data["dst_ap"])
                # print(json_data["src_ap"])
                # print(json_data["timestamp"])


                event = AbnormalFlowModel(
                    type=FLOW_TYPE_PORTSCAN,
                    time=json_data["timestamp"],
                    src=json_data["src_ap"],
                    dst=json_data["dst_ap"],
                    detail=json_data["timestamp"])
                message = pickle.dumps(event)
                if "SNMP" or "SCAN" in json_data["msg"]:
                    print(message)
                self.MQ_Event.send(self.MQ_Event_Topic, message)

# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config


if __name__ == '__main__':
    args_config = init_config('../../config.yaml')
    # port_scan
    port_scan_producer = KafkaProducer(bootstrap_servers=args_config['mq']['bootstrap_servers'])
    port_scan_detector = Port_Scan_Detector(event_producer=port_scan_producer,
                                            topic=args_config['mq']['port_scan_id'],
                                            password=args_config['abnormal_traffic']['port_scan']['password'],
                                            luapath=args_config['abnormal_traffic']['port_scan']['luapath'],
                                            snortpath=args_config['abnormal_traffic']['port_scan']['snortpath'],
                                            interface=args_config['abnormal_traffic']['port_scan']['interface'])
    port_scan_detector.detect()
