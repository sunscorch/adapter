# -*- coding: utf-8 -*-


from pymodbus.client.sync import ModbusSerialClient
from typing import Final
import logging
from logging import handlers
import os
from logging.handlers import TimedRotatingFileHandler
from logging.handlers import RotatingFileHandler
import re
import json
import time
from collections import OrderedDict
import traceback
import sys
import requests
import sched, time
import schedule

offset: Final = 32
start_addr: Final = 5
slave_id: Final = 1
trigger_time: Final = 30
heartbeat_trigger_time: Final = 25
top_server_url: Final = "http://127.0.0.1:8080/api/v1/measvalue-ai/"
top_server_login_url = "http://127.0.0.1:80/api/v1/login"
top_server_heartbeat_url = "http://127.0.0.1:80/api/v1/heartbeat"
login_json: Final = json.loads('{"address":"2","userName":"user", "pwd":"MTIz"}')

conf_mp = OrderedDict()
amplify_mp: Final = {0: 1, 1: 10, 2: 100, 3: 1000}
max_view_send_list = []
token = None

client = ModbusSerialClient(
    method='rtu',
    port='com3',
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
    def __init__(self, objectId, cv, time):
        self.objectId = objectId
        self.cv = cv
        self.time = time

    def __str__(self):
        return "[" + str(self.objectId) + ":" + str(self.cv) + "]"


def combineDigit2Hex(l):
    s = 0
    for elem in l:
        # convert to hex 为每个寄存器补全4位
        hex_num = int("{0:#0{1}X}".format(elem, 4), 16)
        s = s * 16 * 16 * 16 * 16 + hex_num
    print(s)
    return s


def procress_gas_name(l):
    res = ""
    for elem in l:
        # 读取每个寄存器的hex， 然后分割处每个 byte 处理, 转ascii ，00 跳过
        # eg 43 4f 00 00 00 00 => CO
        hex_str = "{0:0{1}X}".format(elem, 4)
        print(hex_str)
        if (hex_str == "0000"):
            continue
        else:
            first_byte = hex_str[0:2]
            print("first byte str is" + first_byte)
            if (first_byte == "00"):
                continue
            res += chr(int(first_byte, 16))
            print("first_byte is {}".format(int(first_byte, 16)))
            second_byte = hex_str[2:]
            if (second_byte == "00"):
                continue
            res += chr(int(second_byte, 16))
    print("the gas name is {}".format(res))
    return res


def read_obj_id():
    f = open('conf.json', 'r')
    content = f.read()
    conf_json = json.loads(content)
    print(conf_json)
    f.close()

    global conf_mp
    for elem in conf_json:
        k = elem["channel"]
        v = elem["objid"]
        conf_mp[k] = v
    # scheduler_object.get_job(job_id ="my_job_id").modify(next_run_time=datetime.datetime.now())
    print("conf_mp is ")
    print(conf_mp)


def get_cv_each_addr(address):
    v = None
    n = None
    cv = None
    if client.connect():  # Trying for connect to Modbus Server/Slave
        res = client.read_holding_registers(address=address, count=2, unit=slave_id)
        # print(combineDigit2Hex(res))
        logger.info(
            "process gas value channel address{}, id is {}".format(address, (address - start_addr) / offset + 1))
        if not res.isError():
            v = combineDigit2Hex(res.registers)
            logger.info("adrress is {0}, channel id is {1}, gas original value is {2}".format(address, (
                    address - start_addr) / offset + 1, v))
        else:
            logger.error("fail to get gas original value from address {}， error:{}".format(address, res))
        # 处理放大你倍数
        res = client.read_holding_registers(address=address + 6, count=1, unit=slave_id)
        # print(combineDigit2Hex(res))
        logger.info(
            "process amplify channel address{}, id is {}".format(address + 6, (address - start_addr) / offset + 1))
        if not res.isError():
            n = combineDigit2Hex(res.registers)
            logger.info("amplify value is {}".format(n))
            print(combineDigit2Hex(res.registers))
        else:
            print(res)
            logger.error("fail to get amplify value , {}".format(res))
    else:
        logger.error('Cannot connect to the Modbus Server/Slave')
    client.close()
    if (v != None and n != None):
        cv = v / amplify_mp[n]
        logger.info("final gas res =  {}".format(cv))
    return cv


# address, the first address stores gas name,  6 bytes offest in all
# 传入气体名称首地址 处理
def get_gas_name(address):
    res = ""
    if client.connect():  # Trying for connect to Modbus Server/Slave
        res = client.read_holding_registers(address=address, count=6, unit=slave_id)
        # print(combineDigit2Hex(res))
        logger.info("process gas name address {} ".format(address))
        if not res.isError():
            v = procress_gas_name(res.registers)
            res = v
            logger.info("gas original value is ".format(address, (address - start_addr) / offset + 1))
        else:
            logger.error("fail to get gas original value from address {}， error:{}".format(address, res))
        client.close()
        print("gas name is " + v)
        return v


def get_n_byte_data(address, n):
    res = None
    if client.connect():  # Trying for connect to Modbus Server/Slave
        res = client.read_holding_registers(address=address, count=n, unit=slave_id)
        logger.info("process  address {} ".format(address))
        if not res.isError():
            v = combineDigit2Hex(res.registers)
            res = v
            logger.info("value is {}".format(res))
        else:
            logger.error("fail to  value from address {}， error:{}".format(address, res))
        client.close()
        return res


def probe(n):
    for i in range(n):
        start_addr_cur = start_addr
        gas_name_addr = start_addr_cur + 3
        gas_name = get_gas_name(gas_name_addr)
        gas_unit = get_n_byte_data(start_addr_cur + 7)
        low_warning_theshold = get_n_byte_data(start_addr_cur + 8, 1)
        high_warning_threshold = get_n_byte_data(start_addr_cur + 9, 1)
        start_addr_cur += offset


def collect_modbus_data():
    global max_view_send_list
    global conf_mp
    start_addr_cur = start_addr
    try:
        # start_addr_cur = start_addr
        if len(conf_mp) == 0:
            logger.error("please set up the conf.json first")
            sys.exit()
        for key, value in conf_mp.items():
            print([key, value])
            cv = None
            try:
                cv = get_cv_each_addr(start_addr_cur)
            except Exception:
                logger.error(u'Failed to get cv data at address {}'.format(start_addr_cur), exc_info=True)

            cur_time = round(time.time() * 1000)
            data = AoObj(value, cv, cur_time)
            max_view_send_list.append(data)
            start_addr_cur += offset

    except Exception as e:
        logger.error(u'Failed to get cv data at address {}'.format(start_addr_cur), exc_info=True)
    else:
        try:
            headers = {'Content-Type': 'application/json; charset=utf-8', }
            logger.info("max_view_send_list is {}".format(' '.join(map(str, max_view_send_list))))

            list_str = json.dumps([ob.__dict__ for ob in max_view_send_list])
            new_data = json.loads(list_str)
            logger.info("send out ai json is {}".format(new_data))
            global top_server_url
            response = requests.post(top_server_url, headers=headers, json=new_data)
            logger.info(response.text)
        except Exception as e:
            logger.error(u'Failed to send out data to top server', exc_info=True)

    finally:
        max_view_send_list = []


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
        if (msg == None):
            logger.error("fail to send heartbeat to server")
        else:
            logger.error("succeed to send heartbeat to server")
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
    s = sched.scheduler(time.time, time.sleep)  # 生成调度器
    print("===========")
    logger.info(argv[0])
    logger.info(argv[1])
    mode = argv[1]
    if (mode == "init"):
        if (len(argv) != 3):
            print("pls end channel number")
            logger.error("pls end channel number")
            sys.exit()
        n = argv[2]
        probe(n)
    elif (mode == "daemon"):
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


logger = setup_log("adapterlog.log")
logger.info("start up the adapter...")

if __name__ == "__main__":
    main(sys.argv)
