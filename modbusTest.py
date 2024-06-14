# -*- coding: utf-8 -*-
import pickle

from pymodbus.client.sync import ModbusSerialClient
from typing import Final
import logging
import os
from logging.handlers import TimedRotatingFileHandler
import re
import json
from collections import OrderedDict
import sys
import requests
import time
import schedule
import base64

serial_port_name: Final = 'com3'
offset: Final = 32
start_addr: Final = 5
# slave_id: Final = 1
trigger_time: Final = 5
heartbeat_trigger_time: Final = 25
top_server_url: Final = "http://127.0.0.1:80/api/v1/measvalue-ai/"
top_server_alarm_url: Final = "http://127.0.0.1:80/api/v1/new-alarms/"
top_server_login_url = "http://127.0.0.1:80/api/v1/login"
top_server_heartbeat_url = "http://127.0.0.1:80/api/v1/heartbeat"

adapter_address = "2"
adapter_usr = "2"
adpater_pwd = "123"
login_json: Final = json.loads('{"address":"2","userName":"user", "pwd":"MTIz"}')

alarm_code_json: Final = '''

{
    "CO": {
        "alarmTypeID": 43,
        "objTypeID": 109
    },
    "O2": {
        "alarmTypeID": 47,
        "objTypeID": 110
    },
    "CH4": {
        "alarmTypeID": 51,
        "objTypeID": 111
    },
    "H2S": {
        "alarmTypeID": 55,
        "objTypeID": 112
    }
}

'''
# 用于告警的code
alarm_code: Final = json.loads(alarm_code_json)

# dict <channel , [低报警， 高报警, 气体名称]>
threshold_dict = dict()

conf_mp = OrderedDict()  # <channel , objid>

max_view_send_list = []
alarm_list = []
token = None

client = ModbusSerialClient(
    method='rtu',
    port=serial_port_name,
    baudrate=9600,
    timeout=3,
    parity='N',
    stopbits=1,
    bytesize=8
)


def setup_log(log_name):
    # 创建logger对象。传入logger名字
    folder = os.path.exists("adapterLog")
    if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
        os.makedirs("adapterLog")
    logger = logging.getLogger(log_name)
    log_path = os.path.join("adapterLog", log_name)
    # 设置日志记录等级
    logger.setLevel(logging.INFO)
    # interval 滚动周期，
    # when="MIDNIGHT", interval=1 表示每天0点为更新点，每天生成一个文件
    # backupCount  表示日志保存个数
    file_handler = TimedRotatingFileHandler(
        filename=log_path, when="MIDNIGHT", interval=1, backupCount=30, encoding='utf-8'
    )
    print(log_path)
    # filename="mylog" suffix设置，会生成文件名为mylog.2020-02-25.log
    file_handler.suffix = "%Y-%m-%d.log"
    # extMatch是编译好正则表达式，用于匹配日志文件名后缀
    # 需要注意的是suffix和extMatch一定要匹配的上，如果不匹配，过期日志不会被删除。
    file_handler.extMatch = re.compile(r"^\d{4}-\d{2}-\d{2}.log$")
    # 定义日志输出格式
    file_handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(process)d] [%(levelname)s] - %(module)s.%(funcName)s (%(filename)s:%(lineno)d) - %(message)s"
        )
    )
    logger.addHandler(file_handler)
    return logger


class AoObj:
    def __init__(self, objectId, cv, cur_time):
        self.objectId = objectId
        self.cv = cv
        self.time = cur_time

    def __str__(self):
        return "[" + str(self.objectId) + ":" + str(self.cv) + "]"


class AlarmEvent:
    def __init__(self, alarmID, alarmName, objTypeID, alarmTypeID, time, objectId, alarmSeverity, acked, ackTime,
                 ackResult, cleared, additionalText):
        self.alarmID = alarmID
        self.alarmName = alarmName
        self.objTypeID = objTypeID
        self.alarmTypeID = alarmTypeID
        self.time = time
        self.objectId = objectId
        self.alarmSeverity = alarmSeverity
        self.acked = acked
        self.ackTime = ackTime
        self.ackResult = ackResult
        self.cleared = cleared
        self.additionalText = additionalText

        # Optional attributes
        self.address = None
        self.alarmSource = None
        self.confirmDesc = None
        self.longitude = None
        self.latitude = None
        self.ackUser = None
        self.clearedUser = None
        self.clearedTime = None

    def __str__(self):
        return f"AlarmID: {self.alarmID}, AlarmName: {self.alarmName}, ObjectTypeID: {self.objTypeID}, " \
               f"AlarmTypeID: {self.alarmTypeID}, Time: {self.time}, ObjectID: {self.objectId}, " \
               f"AlarmSeverity: {self.alarmSeverity}, Acked: {self.acked}, AckTime: {self.ackTime}, " \
               f"AckResult: {self.ackResult}, Cleared: {self.cleared}" \
               f"additionalText: {self.additionalText}"


# 创建AlarmEvent对象实例
# alarm1 = AlarmEvent(alarmID=1, alarmName="High Temperature", objTypeID=101, alarmTypeID=201, time=1648761600, objectId=1,
# alarmSeverity=2, acked=True, ackTime=1648761700, ackResult=1, cleared=False)

# l 是长度为2 的array
def combineDigit2Hex(hex_list):
    combined_value = (hex_list[0] << 16) | hex_list[1]
    return combined_value


def process_gas_name(hex_values):
    # Initialize an empty string to store the ASCII characters
    ascii_result = ""

    # Loop through each 16-bit hex value
    for hex_val in hex_values:
        # Convert the high byte to ASCII and append to result
        high_byte = (hex_val >> 8) & 0xFF  # Shift right by 8 bits and mask to get the high byte
        if high_byte == 0:
            continue
        ascii_result += chr(high_byte)

        # Convert the low byte to ASCII and append to result
        low_byte = hex_val & 0xFF  # Mask to get the low byte
        if low_byte == 0:
            continue
        ascii_result += chr(low_byte)

    return ascii_result


def read_obj_id():
    f = open('conf.json', 'r')
    content = f.read()
    conf_json = json.loads(content)
    print(conf_json)
    f.close()

    global conf_mp
    conf_mp = conf_json
    # scheduler_object.get_job(job_id ="my_job_id").modify(next_run_time=datetime.datetime.now())
    print("conf_mp is ")
    print(conf_mp)


def peocess_alarm(channel, alarm_status, cv, low, high, gas_name, objid):

    if alarm_status == 0:
        return
    alarm_name = gas_name + ("高报警" if alarm_status == 2 else "高报警")

    additionalText = f"{gas_name}当前值{cv}, 正常区间为[{low},{high}]"

    alarm = AlarmEvent(alarmID=1, alarmName=alarm_name, objTypeID=alarm_code[gas_name]['objTypeID'],
                       alarmTypeID=alarm_code[gas_name]['alarmTypeID'],
                       time=round(time.time() * 1000), objectId=objid, alarmSeverity=2,
                       acked=False, ackTime=None, ackResult=1, cleared=False, additionalText=additionalText)
    alarm_list.append(alarm)


def get_cv_each_addr(address, channel, slave_id, objid):
    v = None
    n = None
    cv = None
    if client.connect():  # Trying for connect to Modbus Server/Slave
        # 读取每个通道的所有寄存器的数据 16-5+1 = 12
        res = client.read_holding_registers(address=address, count=12, unit=slave_id)
        # print(combineDigit2Hex(res))
        logger.info(
            "process gas value channel address {}, channel id is {}".format(address, channel))
        if not res.isError():

            reg = res.registers
            # 获取气体浓度数组 为数组的1,2位
            concentration_arr = [reg[0], reg[1]]
            v = combineDigit2Hex(concentration_arr)
            logger.info("address is {}, channel id is {}, gas original value is {}".format(address, (
                    address - start_addr) / offset + 1, v))

            # 处理放大倍数
            amplify_num = reg[5]
            # 放大倍数为10^N次方
            amplify_num = 10 ** amplify_num

            alarm_status = reg[2]

            cv = v / amplify_num
            low_warning_threshold = combineDigit2Hex([reg[8], reg[9]])
            high_warning_threshold = combineDigit2Hex([reg[10], reg[11]])
            gas_name = process_gas_name([reg[3], reg[4], reg[5]])
            peocess_alarm(channel, alarm_status, cv, low_warning_threshold, high_warning_threshold, gas_name, objid)
            logger.info("final gas res =  {}".format(cv))
            return cv
        else:
            logger.error("fail to get gas original value from address {}， error:{}".format(address, res))

    else:
        logger.error('Cannot connect to the Modbus Server/Slave')
    client.close()


def probe(n, slave_id):
    f = open(f"channelInfo{slave_id}.csv", "w")
    try:
        csv_header = ["id", "gas_value", "gas_name", "amplify_value", "low_warning_threshold",
                      "high_warning_threshold"]
        f.writelines(",".join(csv_header) + "\n")
        start_addr_cur = start_addr
        if client.connect():
            for i in range(n):
                res = client.read_holding_registers(address=start_addr_cur, count=12, unit=slave_id)
                if not res.isError():
                    reg = res.registers
                    # 获取气体浓度数组 为数组的1,2位
                    concentration_arr = [reg[0], reg[1]]
                    v = combineDigit2Hex(concentration_arr)
                    # 处理放大倍数
                    amplify_num = res.registers[5]
                    # 放大倍数为10^N次方
                    amplify_num = 10 ** amplify_num

                    gas_value = v / amplify_num

                    gas_name = process_gas_name([reg[3], reg[4], reg[5]])

                    low_warning_threshold = combineDigit2Hex([reg[8], reg[9]])
                    high_warning_threshold = combineDigit2Hex([reg[10], reg[11]])

                    csv_value = [str(i + 1), str(gas_value), str(gas_name), str(amplify_num),
                                 str(low_warning_threshold),
                                 str(high_warning_threshold)]
                    print(csv_value)
                    threshold_dict[i + 1] = [low_warning_threshold, high_warning_threshold, gas_name]
                    f.writelines(",".join(csv_value) + "\n")
                    start_addr_cur += offset
                else:
                    logger.error("fail to get gas original value from address {}， error:{}".format(start_addr_cur, res))
        else:
            logger.error('Cannot connect to the Modbus Server/Slave')

    except Exception:
        logger.error(u'Failed to generate channel info file', exc_info=True)
    finally:

        f.close()


def collect_modbus_data():
    global max_view_send_list
    global alarm_list
    global conf_mp
    start_addr_cur = start_addr
    try:
        # start_addr_cur = start_addr
        if len(conf_mp) == 0:
            logger.error("please set up the conf.json first")
            sys.exit()
        for item in conf_mp:
            slave_id, channel, objid = item['slave_id'], item['channel'], item['objid']
            print([slave_id, channel, objid])
            cv = None
            start_addr_cur = start_addr + (channel - 1) * offset
            try:

                cv = get_cv_each_addr(start_addr_cur, channel, slave_id, objid)
            except Exception:
                logger.error(u'Failed to get cv data at address {}'.format(start_addr_cur), exc_info=True)

            cur_time = round(time.time() * 1000)
            if cv is not None:
                data = AoObj(objid, cv, cur_time)
                max_view_send_list.append(data)
            #start_addr_cur += offset

    except Exception as e:
        logger.error(u'Failed to get cv data at address {}'.format(start_addr_cur), exc_info=True)
    else:
        try:
            headers = {'Content-Type': 'application/json; charset=utf-8', }
            logger.info("max_view_send_list is {}".format(' '.join(map(str, max_view_send_list))))
            logger.info("alarm list is {}".format(alarm_list))

            list_str = json.dumps([ob.__dict__ for ob in max_view_send_list])
            new_data = json.loads(list_str)
            logger.info("send out ai json is {}".format(new_data))
            global top_server_url
            response = requests.post(top_server_url, headers=headers, json=new_data)
            logger.info(response.text)

            list_str = json.dumps([ob.__dict__ for ob in alarm_list])
            new_data = json.loads(list_str)
            logger.info("send out alarm json is {}".format(new_data))
            global top_server_alarm_url
            response = requests.post(top_server_alarm_url, headers=headers, json=new_data)
            logger.info(response.text)

        except Exception as e:
            logger.error(u'Failed to send out data to top server', exc_info=True)

    finally:
        max_view_send_list = []
        alarm_list = []


def heartbeat():
    try:
        headers = {'Content-Type': 'application/json;charset=utf-8', }
        global token
        if token is None:
            token = login()
        if token is None:
            logger.error("fail to get token through login")
            return
        time.sleep(2)
        token_json = json.loads("""{{"token": "{}" }}""".format(token))
        logger.info("heartbeat request json is {}".format(token_json))
        r = requests.post(top_server_heartbeat_url, headers=headers, json=token_json)
        logger.info("heartbeat response is {}".format(r.text))
        msg = json.loads(r.text).get('msg')
        token = msg
        if msg is None:
            token = None
            logger.error("fail to send heartbeat to server")
        else:
            logger.info("succeed to send heartbeat to server")
    except Exception as e:
        logger.error(u'Failed to send out heartbeat....', exc_info=True)


def login():
    headers = {'Content-Type': 'application/json;charset=utf-8', }
    r = requests.post(top_server_login_url, headers=headers, json=login_json)
    logger.info("login json is {}".format(login_json))
    logger.info("login request response is {}".format(r.text))
    msg = json.loads(r.text).get('msg')
    return msg


def main(argv):
    print("===========")
    logger.info(argv[0])
    logger.info(argv[1])
    mode = argv[1]
    if mode == "init":
        if len(argv) != 4:
            print("pls end channel number")
            logger.error("pls end channel number")
            sys.exit()
        n = int(argv[2])
        slave_id = int(argv[3])
        probe(n, slave_id)
    elif mode == "daemon":
        global heartbeat_trigger_time

        logger.info("we are in daemon mode")
        read_obj_id()
        schedule.every(heartbeat_trigger_time).seconds.do(heartbeat)
        schedule.every(trigger_time).seconds.do(collect_modbus_data)
        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        print("invalid args")
        logger.error("invalid args")


logger = setup_log("adapterLog.log")
logger.info("start up the adapter...")

if __name__ == "__main__":
    main(sys.argv)
