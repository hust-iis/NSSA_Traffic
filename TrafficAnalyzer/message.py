MSG_TYPE_TRAFFIC = 0
MSG_TYPE_HOST = 1
MSG_TYPE_USER = 2

class AbnormalEventMSG:
    def __init__(self, type, data) -> None:
        self.type = type
        self.data = data