import pickle
import pymysql
import yaml

from pymysql import Connection
from abnomal_traffic.msg_models.models import AbnormalTraffic
from message import AbnormalEventMSG, MSG_TYPE_HOST


class AbnormalHostMSG:
    def __init__(self, ip, name, detail, time):
        self.ip = ip
        self.name = name
        self.detail = detail
        self.time = time


# def init_config(config_file):
#     with open(config_file, 'r') as f:
#         config = yaml.load(f, Loader=yaml.Loader)
#         return config


class AbnormalHost_send:
    def __init__(self, traffic_consumer, event_producer, topic):
        # 消息队列相关
        self.MQ_Traffic = traffic_consumer
        self.MQ_Event = event_producer
        self.MQ_Event_Topic = topic

    def alert(self, ip, name, detail, time):
        # 创建消息
        event = AbnormalHostMSG(
            ip=ip,
            name=name,
            detail=detail,
            time=time
        )
        # push消息
        message = pickle.dumps(AbnormalEventMSG(type=MSG_TYPE_HOST, data=event))
        self.MQ_Event.send(self.MQ_Event_Topic, message)

    def database_log(self, db_settings_1, db_settings_2):
        con1 = None
        con2 = None
        try:
            con1 = Connection(
                host=db_settings_1['host'],
                port=db_settings_1['port'],
                user=db_settings_1['user'],
                password=db_settings_1['password'],
                database=db_settings_1['name'],
                autocommit=True
            )
            con2 = Connection(
                host=db_settings_2['host'],
                port=db_settings_2['port'],
                user=db_settings_2['user'],
                password=db_settings_2['password'],
                database=db_settings_2['name'],
                autocommit=True
            )

            # 创建游标
            cursor1 = con1.cursor()
            cursor2 = con2.cursor()

            create_table_query = """
                            CREATE TABLE IF NOT EXISTS abnormal_attack_abnormalhost (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                ip varchar(20),
                                name varchar(50) not null,
                                detail text,
                                time datetime DEFAULT CURRENT_TIMESTAMP
                            )
                            """

            cursor1.execute(create_table_query)
            # cursor2.execute("select column_name from INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'abnormal_host' AND TABLE_NAME = 'abnormalhost_info'")
            # results = cursor2.fetchall()
            # print(results)
            select_table_log = "select ip,info,datetime from abnormalhost_info where info like '[新报警]%'"
            cursor2.execute(select_table_log)
            results = cursor2.fetchall()
            detail = ""
            datetime_info = results[0][2]
            cnt = 0
            # insert_query = "insert into abnormal_attack_abnormalhost values (null,%s,%s,%s,%s)"
            for row in results:
                cnt += 1
                ip_info = row[0]
                # asset表中查询ip对应的资产名（数据库名表名字段名未知）
                cursor1.execute("select asset_name from asset where ip = %s", (ip_info,))
                name_info = cursor1.fetchall()
                info_info = row[1]
                if row[2] == datetime_info:
                    detail += info_info
                else:
                    # cursor1.execute(insert_query, [ip_info, name_info, detail, datetime_info])
                    self.alert(ip=ip_info, name=name_info, detail=detail, time=datetime_info)
                    detail = info_info
                datetime_info = row[2]
                if cnt == len(results):
                    # cursor1.execute(insert_query, [ip_info, name_info, detail, datetime_info])
                    self.alert(ip_info, name_info, detail, datetime_info)
                print("ip=%s,name=%s,info=%s,datetime=%s" % \
                      (ip_info, name_info, info_info, datetime_info))
        except Exception as e:
            print(e)
        finally:
            if con1:
                con1.close()
            if con2:
                con2.close()

    def main(self, args_config):
        # args_config = init_config('D:\\NSSA\\NSSA_Traffic\\config.yaml')
        database_info1 = args_config['database1']  # 报警信息存入数据库
        database_info2 = args_config['database2']  # 查询name
        self.database_log(database_info1, database_info2)


# if __name__ == '__main__':
#     main()
