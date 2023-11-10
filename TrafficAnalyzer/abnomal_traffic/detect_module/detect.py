#get ftp file
#detect the file
#delete the file
#send the file to the queue

import os
import yaml
import consumer
import test_detect

def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config
def delete_files_in_folder(folder_path):
    # 获取文件夹中的所有文件
    file_list = os.listdir(folder_path)

    # 遍历文件列表，删除每个文件
    for file_name in file_list:
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)
            print(f"已删除文件: {file_path}")


if '__name__' == '__main__':
    args_config = init_config('../../../config.yaml')
    # 将通过ftp协议传输的文件保存到test文件夹下
    consumer.get_files()
    # 检测test文件夹是否有病毒，木马，蠕虫
    test_detect.detect()
    # 调用函数删除文件夹下的所有文件
    delete_files_in_folder(args_config['deletepath'])

