import yaml
import re
import mysql.connector

def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config
    
def info_to_database(db_settings, info_list):
    # 创建数据库连接
    conn = mysql.connector.connect(
        host=db_settings['host'],
        user=db_settings['user'],
        password=db_settings['password'],
        database=db_settings['name']
    )

    # 创建一个游标对象
    cursor = conn.cursor()

    create_table_query = """
        CREATE TABLE IF NOT EXISTS abnormal_user_info (
            id INT AUTO_INCREMENT PRIMARY KEY,
            type int,
            time datetime DEFAULT CURRENT_TIMESTAMP,
            user_name varchar(50) not null,
            topic varchar(200),
            src_ip varchar(50)
        )
        """
    cursor.execute(create_table_query)


    insert_query = """
        insert into abnormal_user_info(type,user_name,topic,src_ip) values 
    """

    is_first = True
    for item in info_list:
        if is_first == False:
            insert_query += ','
        is_first = False
        ip, user, topic, abnormal = item
        # print(topic)
        insert_query += " (\'%s\',\'%s\',\'%s\',\'%s\')" % (abnormal, user, topic, ip)
        # print(insert_query)
    
    # print(insert_query)
    cursor.execute(insert_query)
    conn.commit()
    
    cursor.close()
    conn.close()


#提取异常用户信息    
def get_user_info(log_file): 

    id_user = dict()
    id_ip = dict()
    info_list = []
    with open(log_file, 'r') as log:
        for line in log:

            ip_match = re.search(r"New client connected from (\d+\.\d+\.\d+\.\d+:\d+) as ([\S-]+) \(.*u'([\S-]+)'", line)
            if ip_match:
                client_id = ip_match.group(2)

                ip = ip_match.group(1)
                id_ip[client_id] = ip

                user = ip_match.group(3)
                id_user[client_id] = user
                # print(client_id)

            err_match = re.search(r"Denied PUBLISH from (\S+).*\'(\S+)\'", line)
            if err_match:
                user = id_user.get(err_match.group(1), 'user not found')
                if user == 'user not found':
                    continue
                ip = id_ip.get(err_match.group(1))
                topic = err_match.group(2)
                abnormal = 1
                # print(topic)
                info_list.append([ip, user, topic, abnormal])

            normal_match = re.search(r"Received PUBLISH from (\S+).*\'(\S+)\'", line)
            if normal_match:
                # if(normal_match.group(1) != 'local.mqttbroker.com.bridge1'):
                #     print(id_user.get(normal_match.group(1)))
                #     print(normal_match.group(2))
                user = id_user.get(normal_match.group(1), 'user not found')
                if user == 'user not found':
                    continue
                ip = id_ip.get(normal_match.group(1))
                topic = normal_match.group(2)
                abnormal = 0
                info_list.append([ip, user, topic, abnormal])
    
    # print(info_list)
    return info_list
    
def main():
    #获取log文件
    args_config = init_config('./config.yaml')
    log_file = args_config['abnormal_user']['log_file']

    #分析log文件
    info_list = get_user_info(log_file)

    # print(info_list)

    if info_list:
        table = ''
        info_to_database(args_config['database'], info_list)

if __name__ == '__main__':
    main()
