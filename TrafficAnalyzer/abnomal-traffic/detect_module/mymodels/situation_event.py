import peewee

# SituationEvent事件类型常量
EVENT_TYPE_DDOS = 1     # DDOS
EVENT_TYPE_WEBSHELL = 2 # Webshell
EVENT_TYPE_BOTNET = 3   # 僵尸网络
EVENT_TYPE_TROJAN = 4   # 木马
EVENT_TYPE_WORM = 5     # 蠕虫
EVENT_TYPE_VIRUS = 6    # 病毒
EVENT_TYPE_SQL_INJECT = 7   # SQL注入
EVENT_TYPE_XML_INJECT = 8   # XML注入
EVENT_TYPE_XSS = 9          # 跨站脚本
EVENT_TYPE_PORT_SCAN = 10   # 端口扫描

class SituationEvent(peewee.Model):
    id = peewee.PrimaryKeyField()   # 主键
    event_type = peewee.IntegerField() # 事件类型：DDoS, Webshell...
    happened_at = peewee.DateTimeField() # 态势事件检测时间
    event_info = peewee.TextField() # 事件信息

    class Meta:
        db_table = 'situation_events'
