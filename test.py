import requests
from bs4 import BeautifulSoup
import json
import sys
from datetime import datetime
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import argparse
import logging
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 硬编码场馆ID映射
LIBRARY_MAPPING = {
    "1": "53",  # 主馆
    "2": "18",  # 基础馆
    "3": "37",  # 农医馆
}

# 硬编码楼层ID映射 (按场馆分类)
FLOOR_MAPPING = {
    "53": {  # 主馆
        "2": "54",  # 二层
        "3": "55",  # 三层
        "4": "56",  # 四层
        "5": "57",  # 五层
    },
    "18": {  # 基础馆
        "1": "22",  # 一层
        "2": "23",  # 二层
        "3": "19",  # 三层
    },
    "37": {  # 农医馆
        "1": "44",  # 一层
        "2": "45",  # 二层
        "3": "46",  # 三层
    }
}

# 硬编码区域ID映射 (按楼层分类)
AREA_MAPPING = {
    "54": ["58", "59"],  # 主馆二层: 二层南, 二层北
    "55": ["60", "61", "62"],  # 主馆三层: 三层东, 三层南, 三层北
    "56": ["63", "64", "65", "66"],  # 主馆四层: 四层东, 四层南, 四层西, 四层北
    "57": ["67"],  # 主馆五层: 五层东
    "22": ["39"],  # 基础馆一层: 一层书库
    "23": ["40"],  # 基础馆二层: 二层书库
    "19": ["21"],  # 基础馆三层: 301信息共享空间
    "44": ["47"],  # 农医馆一层: 112李摩西阅览室
    "45": ["48", "49", "50"],  # 农医馆二层: 207中文图书阅览室, 209中文图书阅览室, 211中文图书阅览室
    "46": ["51", "52"],  # 农医馆三层: 320外文图书阅览室, 322中外文现刊阅览室
}

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='浙江大学图书馆座位预约脚本')
    parser.add_argument('--username', '-u', required=True, help='统一身份认证用户名')
    parser.add_argument('--password', '-p', required=True, help='统一身份认证密码')
    parser.add_argument('--library', '-l', required=True, help='场馆编号(1=主馆, 2=基础馆, 3=农医馆)')
    parser.add_argument('--floor', '-f', required=True, help='楼层编号(1=一层, 2=二层, 3=三层, 4=四层, 5=五层)')
    parser.add_argument('--retry', '-r', type=int, default=3, help='重试次数')
    parser.add_argument('--delay', '-d', type=int, default=5, help='重试延迟(秒)')
    return parser.parse_args()

def login(session, username, password):
    """登录统一身份认证系统"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    zjuam_login_url = "http://zjuam.zju.edu.cn/cas/login?service=https%3A%2F%2Fbooking.lib.zju.edu.cn%2Fapi%2Fcas%2Fcas"
    
    try:
        # 获取登录页面
        zjuam_login_resp = session.get(zjuam_login_url)
        zjuam_login_resp.raise_for_status()
        
        # 获取公钥
        zjuam_pubkey_url = 'https://zjuam.zju.edu.cn/cas/v2/getPubKey'
        zjuam_pubkey_resp = session.get(zjuam_pubkey_url)
        zjuam_pubkey_resp.raise_for_status()
        
        # 加密密码
        password_bytes = bytes(password, 'ascii')
        password_int = int.from_bytes(password_bytes, 'big')
        e_int = int(zjuam_pubkey_resp.json()["exponent"], 16)
        M_int = int(zjuam_pubkey_resp.json()["modulus"], 16)
        result_int = pow(password_int, e_int, M_int)
        encrypt_password = hex(result_int)[2:].rjust(128, '0')
        
        # 提交登录表单
        zjuam_login_headers = {
            'User-Agent': user_agent,
        }
        zjuam_login_data = {
            'username': username,
            'password': encrypt_password,
            '_eventId': 'submit',
            'execution': BeautifulSoup(zjuam_login_resp.text, "html.parser").find("input", attrs={'name': 'execution'})['value'],
            'authcode': '',
        }
        
        zjuam_login_resp = session.post(zjuam_login_url, headers=zjuam_login_headers, data=zjuam_login_data, verify=False)
        zjuam_login_resp.raise_for_status()
        
        if "用户名或密码错误" in zjuam_login_resp.text:
            logger.error("统一身份认证用户名或密码错误")
            return None
        
        return zjuam_login_resp
    
    except requests.exceptions.RequestException as e:
        logger.error(f"登录过程中发生错误: {e}")
        return None

def get_authorization(session, login_resp):
    """获取授权信息"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_user_url = 'http://booking.lib.zju.edu.cn/api/cas/user'
    
    try:
        booking_user_headers = {
            'User-Agent': user_agent,
        }
        booking_user_data = {
            'cas': login_resp.url[login_resp.url.find('cas=') + 4:]
        }
        
        booking_user_resp = session.post(booking_user_url, headers=booking_user_headers, data=booking_user_data)
        booking_user_resp.raise_for_status()
        
        booking_user_data = json.loads(booking_user_resp.text)
        return 'bearer' + booking_user_data['member']['token']
    
    except (requests.exceptions.RequestException, KeyError, json.JSONDecodeError) as e:
        logger.error(f"获取授权信息时发生错误: {e}")
        return None

def get_available_date(session, authorization):
    """获取可预约的日期"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_select_time_url = 'http://booking.lib.zju.edu.cn/reserve/index/quickSelect'
    
    try:
        booking_select_time_headers = {
            'User-Agent': user_agent,
        }
        booking_select_time_data = {
            'id': '1',
            'authorization': authorization,
        }
        
        booking_select_time_resp = session.post(booking_select_time_url, headers=booking_select_time_headers, data=booking_select_time_data)
        booking_select_time_resp.raise_for_status()
        
        booking_select_time_data = json.loads(booking_select_time_resp.text)
        return booking_select_time_data['data']['date'][0]
    
    except (requests.exceptions.RequestException, KeyError, IndexError, json.JSONDecodeError) as e:
        logger.error(f"获取可预约日期时发生错误: {e}")
        return None

def verify_location_ids(session, authorization, date, premises_id, storey_id):
    """验证场馆和楼层ID是否有效"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_select_premises_url = 'http://booking.lib.zju.edu.cn/reserve/index/quickSelect'
    
    try:
        booking_select_premises_headers = {
            'User-Agent': user_agent,
        }
        booking_select_premises_data = {
            'id': '1',
            'date': date,
            'authorization': authorization,
        }
        
        booking_select_premises_resp = session.post(booking_select_premises_url, headers=booking_select_premises_headers, data=booking_select_premises_data)
        booking_select_premises_resp.raise_for_status()
        
        booking_select_premises_data = json.loads(booking_select_premises_resp.text)
        
        # 验证场馆ID
        premises_valid = False
        for i in booking_select_premises_data['data']['premises']:
            if premises_id == i['id']:
                premises_valid = True
                logger.info(f"选择场馆: {i['name']} (ID: {i['id']}, 余量: {i['free_num']}/{i['total_num']})")
                break
        
        if not premises_valid:
            logger.error(f"无效的场馆ID: {premises_id}")
            return False
        
        # 验证楼层ID
        storey_valid = False
        for i in booking_select_premises_data['data']['storey']:
            if storey_id == i['id'] and premises_id == i['topId']:
                storey_valid = True
                logger.info(f"选择楼层: {i['name']} (ID: {i['id']}, 余量: {i['free_num']}/{i['total_num']})")
                break
        
        if not storey_valid:
            logger.error(f"无效的楼层ID: {storey_id}")
            return False
        
        return True
    
    except (requests.exceptions.RequestException, KeyError, json.JSONDecodeError) as e:
        logger.error(f"验证位置ID时发生错误: {e}")
        return False

def get_booking_time(session, authorization):
    """获取预约时间段信息"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_date_url = 'http://booking.lib.zju.edu.cn/api/Seat/date'
    
    try:
        booking_date_headers = {
            'User-Agent': user_agent,
        }
        booking_date_data = {
            'build_id': '59',
            'authorization': authorization,
        }
        
        booking_date_resp = session.post(booking_date_url, headers=booking_date_headers, data=booking_date_data)
        booking_date_resp.raise_for_status()
        
        booking_date = json.loads(booking_date_resp.text)
        return booking_date
    
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error(f"获取预约时间段信息时发生错误: {e}")
        return None

def get_available_seats(session, authorization, area_id, booking_date):
    """获取可用座位信息"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_seat_url = 'http://booking.lib.zju.edu.cn/api/Seat/seat'
    
    try:
        booking_seat_headers = {
            'User-Agent': user_agent,
        }
        booking_seat_data = {
            'area': area_id,
            'segment': booking_date['data'][0]['times'][0]['id'],
            'day': booking_date['data'][0]['day'],
            'startTime': booking_date['data'][0]['times'][0]['start'],
            'endTime': booking_date['data'][0]['times'][0]['end'],
            'authorization': authorization,
        }
        
        booking_seat_resp = session.post(booking_seat_url, headers=booking_seat_headers, data=booking_seat_data)
        booking_seat_resp.raise_for_status()
        
        booking_seat = json.loads(booking_seat_resp.text)
        
        # 统计空闲座位
        free_seats = []
        free_num = 0
        using_num = 0
        
        for i in booking_seat['data']:
            if i['status'] == '6':
                using_num += 1
            elif i['status'] == '1':
                free_num += 1
                free_seats.append(i)
            elif i['status'] == '7':
                using_num += 1
        
        logger.info(f"当前区域共 {free_num} 个空闲座位, {using_num} 个使用中座位")
        
        if free_num == 0:
            logger.info("当前区域座位已满")
            return None
        
        return {
            'free_seats': free_seats,
            'segment': booking_date['data'][0]['times'][0]['id']
        }
    
    except (requests.exceptions.RequestException, KeyError, IndexError, json.JSONDecodeError) as e:
        logger.error(f"获取可用座位信息时发生错误: {e}")
        return None

def book_seat(session, authorization, seat_id, segment):
    """预约座位"""
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    booking_confirm_url = 'http://booking.lib.zju.edu.cn/api/Seat/confirm'
    
    try:
        date = datetime.now().strftime("%Y%m%d")
        key = str(date + date[::-1]).encode('utf-8')
        iv = 'ZZWBKJ_ZHIHUAWEI'.encode('utf-8')
        
        plaintext = f'{{"seat_id":"{seat_id}","segment":"{segment}"}}'.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
        
        booking_confirm_headers = {
            'User-Agent': user_agent,
            'authorization': authorization,
        }
        booking_confirm_data = {
            'aesjson': ciphertext_base64,
            'authorization': authorization,
        }
        
        booking_confirm_resp = session.post(booking_confirm_url, headers=booking_confirm_headers, data=booking_confirm_data)
        booking_confirm_resp.raise_for_status()
        
        result = json.loads(booking_confirm_resp.text)
        return result
    
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logger.error(f"预约座位时发生错误: {e}")
        return None

def main():
    """主函数"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 禁用不安全请求警告
    urllib3.disable_warnings()
    
    # 创建会话
    session = requests.session()
    
    # 将用户输入的简化编号转换为实际ID
    if args.library not in LIBRARY_MAPPING:
        logger.error(f"无效的场馆编号: {args.library}，有效值为: 1(主馆), 2(基础馆), 3(农医馆)")
        sys.exit(1)
    
    premises_id = LIBRARY_MAPPING[args.library]
    
    if args.floor not in FLOOR_MAPPING.get(premises_id, {}):
        logger.error(f"无效的楼层编号: {args.floor}，或该场馆不存在此楼层")
        sys.exit(1)
    
    storey_id = FLOOR_MAPPING[premises_id][args.floor]
    
    # 登录
    logger.info(f"正在使用用户名 {args.username} 登录...")
    login_resp = login(session, args.username, args.password)
    if not login_resp:
        sys.exit(1)
    
    # 获取授权信息
    authorization = get_authorization(session, login_resp)
    if not authorization:
        sys.exit(1)
    
    # 获取可预约日期
    date = get_available_date(session, authorization)
    if not date:
        sys.exit(1)
    logger.info(f"预约日期: {date}")
    
    # 验证场馆和楼层ID
    if not verify_location_ids(session, authorization, date, premises_id, storey_id):
        sys.exit(1)
    
    # 获取预约时间段信息
    booking_date = get_booking_time(session, authorization)
    if not booking_date:
        sys.exit(1)
    
    # 获取该楼层的所有区域
    area_ids = AREA_MAPPING.get(storey_id, [])
    if not area_ids:
        logger.error(f"该楼层没有可用区域")
        sys.exit(1)
    
    # 尝试预约每个区域的座位
    for area_id in area_ids:
        logger.info(f"正在尝试区域ID: {area_id}")
        
        # 获取可用座位
        seats_info = get_available_seats(session, authorization, area_id, booking_date)
        if not seats_info or not seats_info['free_seats']:
            logger.info(f"区域 {area_id} 没有可用座位，尝试下一个区域")
            continue
        
        # 选择第一个可用座位
        selected_seat = seats_info['free_seats'][0]
        logger.info(f"选择座位: {selected_seat['name']} (ID: {selected_seat['id']})")
        
        # 预约座位
        retry_count = 0
        while retry_count < args.retry:
            logger.info(f"正在预约座位 {selected_seat['name']} (ID: {selected_seat['id']})...")
            result = book_seat(session, authorization, selected_seat['id'], seats_info['segment'])
            
            if result and 'msg' in result:
                logger.info(f"预约结果: {result['msg']}")
                
                # 如果预约成功或者错误信息不是因为座位被占用，则退出循环
                if '成功' in result['msg'] or ('已经' in result['msg'] and '被预约' not in result['msg']):
                    logger.info(f"预约成功！场馆: {premises_id}, 楼层: {storey_id}, 区域: {area_id}, 座位: {selected_seat['id']}")
                    return
            
            retry_count += 1
            if retry_count < args.retry:
                logger.info(f"预约失败，{args.delay}秒后进行第{retry_count+1}次重试...")
                time.sleep(args.delay)
        
        logger.info(f"区域 {area_id} 预约失败，尝试下一个区域")
    
    logger.error("所有区域都无法预约座位")
    sys.exit(1)

if __name__ == "__main__":
    main()