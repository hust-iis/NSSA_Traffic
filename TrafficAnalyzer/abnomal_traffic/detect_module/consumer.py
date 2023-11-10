import os
import shutil

import yaml
import pickle
from kafka import KafkaConsumer


# 解析配置
def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

#get ftp files
def get_files():
    # 获取配置
    args_config = init_config('../../../config.yaml')
    # 设置消息队列

    consumer = KafkaConsumer(
        # 'net-traffic',
        # bootstrap_servers=['localhost:9092']
        args_config['mq']['traffic_topic'],
        bootstrap_servers=args_config['mq']['server']
    )
    filename = "other.abc"
    # 获取流量包
    for msg in consumer:
        # print(msg)
        pkt = pickle.loads(msg.value)
        # 确定传输文件名以及后缀
        my_request_command = ""
        my_request_arg = ""
        print(len(pkt.layers))
        if len(pkt.layers) >= 4:
            if pkt.layers[3].layer_name == 'ftp':
                ftp_pkt = pkt.layers[3]
                print("看看ftp输出")
                print(pkt.layers[3].field_names)
                if 'request_command' in pkt.layers[3].field_names:
                    print("request_command")
                    my_request_command = pkt.layers[3].request_command
                    print(pkt.layers[3].request_command)
                if 'request_arg' in pkt.layers[3].field_names:
                    print("request_arg")
                    my_request_arg = pkt.layers[3].request_arg
                    print(pkt.layers[3].request_arg)
                if my_request_command == 'RETR':
                    filename = my_request_arg
        if filename =='other.abc':
            continue
        else:
            # 保存FTP中传输的文件数据为文件用于病毒检测
            print(pkt.highest_layer)
            if pkt.highest_layer == 'DATA-TEXT-LINES':
                print("看看完整的FTP-DATA pkt")
                ftp_data = pkt.layers[9]
                with open('./test/data.txt''', 'w') as f:
                    f.write(str(ftp_data))
                print("successfully write my file")

                # 读取文件 调整内容
                lines = []
                with open('./test/data.txt') as f:
                    f.readline()
                    line = f.readline()
                    if line:
                        line = line[1:]  # 删除第二行第一个字符
                        line = line.strip("\t")
                        line = line[:-3]
                        lines.append(line)
                    for line in f:
                        line = line.strip("\t")
                        line = line[:-3]
                        print("不知道哪一行", line)
                        lines.append(line)

                # 创建新文件并写入内容
                with open('./test/new_data.txt', 'w') as f:
                    for line in lines:
                        f.write(line + "\n")

                # 删除原文件
                os.remove('./test/data.txt')
                # 修改新文件名称为原文件名
                # os.rename('new_data.txt', 'data.txt')
                os.rename('./test/new_data.txt', filename)
                shutil.move(filename, args_config['deletepath'])
                filename = 'other.abc'
                # 查看获得的文件
                # with open(filename, 'r') as f:
                #     test_info = f.read()
                # print(test_info)
                # print("successfully read my file")


if __name__ == '__main__':
    get_files()
