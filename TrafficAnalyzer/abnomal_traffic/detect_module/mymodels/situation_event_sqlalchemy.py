from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base

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

Base = declarative_base()

class SituationEvent(Base):
    __tablename__ = "situation_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(Integer)
    happened_at = Column(DateTime)
    event_info = Column(String(length=200))

def Create_Tables(engine):
    Base.metadata.create_all(engine)
