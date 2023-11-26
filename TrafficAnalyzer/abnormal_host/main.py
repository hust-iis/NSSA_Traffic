import pymysql
import yaml
from pymysql import Connection

def init_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
        return config

# def info_to_database(db_settings):
#     con1 = None
#     try:
#
#         con1 = Connection(
#             host=db_settings['host'],
#             port=db_settings['port'],
#             user=db_settings['user'],
#             password=db_settings['password'],
#             database=db_settings['name']
#         )
#
#         # 创建游标
#         cursor = con1.cursor()
#
#         create_table_query = """
#                 CREATE TABLE IF NOT EXISTS abnormal_attack_abnormalhost (
#                     id INT AUTO_INCREMENT PRIMARY KEY,
#                     ip varchar(20),
#                     name varchar(50) not null,
#                     errprint varchar(200),
#                     time datetime DEFAULT CURRENT_TIMESTAMP
#                 )
#                 """
#
#         cursor.execute(create_table_query)
#
#
#
#     except Exception as e:
#         print(e)
#     finally:
#         if con1:
#             con1.close()

def database_log(db_settings_1, db_settings_2):
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
            autocommit = True
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
        for row in results:
            cnt += 1
            ip_info = row[0]
            info_info = row[1]
            if row[2] == datetime_info:
                detail += info_info
            else:
                insert_query = "insert into abnormal_attack_abnormalhost values (null,%s,'123',%s,%s)"
                cursor1.execute(insert_query, [ip_info, detail, datetime_info])
                detail = info_info
            datetime_info = row[2]
            if cnt == len(results):
                insert_query = "insert into abnormal_attack_abnormalhost values (null,%s,'123',%s,%s)"
                cursor1.execute(insert_query, [ip_info, detail, datetime_info])
            print("ip=%s,info=%s,datetime=%s" % \
                  (ip_info, info_info, datetime_info))
        con1.commit()

    except Exception as e:
        print(e)
    finally:
        if con1:
            con1.close()
        if con2:
            con2.close()

def main():
    args_config = init_config('D:\\NSSA\\NSSA_Traffic\\config.yaml')
    database_info1 = args_config['database1']
    database_info2 = args_config['database2']
    database_log(database_info1,database_info2)



if __name__ == '__main__':
    main()
