import asyncio
import json
import sys
import logging
from pathlib import Path
from datetime import date, timedelta, timezone
import io
import urllib.parse # 确保导入
from typing import Optional, Dict, Any, List
import datetime # 确保导入 (用于 AES 加密 和 抢座逻辑)


# 导入必要的库
import httpx
from httpx import HTTPStatusError, ConnectTimeout
from lxml import etree
import traceback
#输入seat_id和segment,输出confirmAPI所需的aesjson值
import json
import base64
# (datetime 已在上方导入)
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 1. 从 JavaScript 代码中获取的硬编码 IV
HARDCODED_IV = "ZZWBKJ_ZHIHUAWEI"
BEIJING_TZ = timezone(timedelta(hours=8))

def generate_dynamic_key() -> str:
    """
    修正逻辑：
    规则: [YYYYMMDD] + [reverse(YYYYMMDD)]
    这会产生一个 16 字节的 Key。
    """
    now_beijing = datetime.datetime.now(BEIJING_TZ)
    date_str = now_beijing.strftime("%Y%m%d")
    
    # 2. 反转字符串
    reversed_str = date_str[::-1]
    
    # 3. (修正) 直接拼接，不再去掉第一位
    dynamic_key = date_str + reversed_str
    
    return dynamic_key

def do_encrypt(plaintext_str: str, key_str: str, iv_str: str) -> str:
    """
    核心加密函数：
    - 模拟 CryptoJS.AES.encrypt
    - 使用 AES-CBC-Pkcs7
    - 密钥和IV使用 UTF-8 编码
    - 输出为 Base64 字符串
    """
    
    # 1. 将密钥、IV 和明文转换为 bytes
    #    (此时 key_str 和 iv_str 都必须是 16 字节长)
    key_bytes = key_str.encode('utf-8')
    iv_bytes = iv_str.encode('utf-8')
    plaintext_bytes = plaintext_str.encode('utf-8')

    # 2. 创建 AES 密码器 (CBC 模式)
    #    (现在 key_bytes 和 iv_bytes 都是 16 字节，不会报错)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

    # 3. 对明文进行 Pkcs7 填充
    padded_data = pad(plaintext_bytes, AES.block_size, style='pkcs7')

    # 4. 执行加密
    ciphertext_bytes = cipher.encrypt(padded_data)

    # 5. 将加密后的 bytes 转换为 Base64 字符串
    encrypted_base64 = base64.b64encode(ciphertext_bytes).decode('utf-8')

    return encrypted_base64

def get_encrypted_seat_request(seat_id: str, segment: str) -> dict:
    """
    封装业务逻辑，生成最终的请求体。
    (用于 /api/Seat/confirm API)
    """
    
    # 1. 自动生成 16 字节的动态 Key
    dynamic_key = generate_dynamic_key()
    logger.debug(f"[*] Generated Dynamic Key: {dynamic_key} (Length: {len(dynamic_key)})")
    logger.debug(f"[*]          Hardcoded IV: {HARDCODED_IV} (Length: {len(HARDCODED_IV)})")

    # 2. 构建明文 payload
    payload = {
        "seat_id": str(seat_id),
        "segment": str(segment)
    }

    # 3. 将 payload 转换为紧凑的 JSON 字符串
    plaintext_json = json.dumps(payload, separators=(',', ':'))
    logger.debug(f"[*] Plaintext JSON: {plaintext_json}")

    # 4. 使用动态 key 和硬编码 IV 进行加密
    encrypted_data = do_encrypt(plaintext_json, dynamic_key, HARDCODED_IV)

    # 5. 构建最终的请求体
    final_payload = {
        "aesjson": encrypted_data
    }

    return final_payload

# ----------------------------------------------------------------------
# 1. 配置日志
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# 2. 核心依赖: RSA 加密工具 (未修改)
# ----------------------------------------------------------------------
class ZjuRSA:
    """
    封装浙大统一身份认证系统 (CAS) 所需的 RSA 加密逻辑。
    此部分代码源自对登录页 JS 逻辑的逆向工程，无需修改。
    """
    
    @staticmethod
    def _create_rsa_key(public_exponent_hex: str, modulus_hex: str) -> object:
        class RSAKeyPython:
            def __init__(self, public_exponent_hex: str, modulus_hex: str):
                self.e = int(public_exponent_hex, 16)
                self.m = int(modulus_hex, 16)
                if self.m == 0: raise ValueError("Modulus cannot be zero.")
                num_16bit_words_m = (self.m.bit_length() + 15) // 16
                bi_high_index_m = max(0, num_16bit_words_m - 1)
                self.chunkSize = 2 * bi_high_index_m 
                self.radix = 16 
        return RSAKeyPython(public_exponent_hex, modulus_hex)

    @staticmethod
    def _encrypted_string(key: object, s: str) -> str:
        char_codes = [ord(char_in_s) for char_in_s in s]
        if key.chunkSize == 0:
            if not char_codes: return ""      
            raise ValueError("key.chunkSize is 0.")
        current_len = len(char_codes)
        padding_count = 0
        if current_len % key.chunkSize != 0:
            padding_count = key.chunkSize - (current_len % key.chunkSize)
        char_codes.extend([0] * padding_count)
        al = len(char_codes)
        result_parts = []
        for i in range(0, al, key.chunkSize):
            current_block_bytes_source = char_codes[i : i + key.chunkSize]
            block_int = int.from_bytes(bytes(current_block_bytes_source), byteorder='little')
            encrypted_int = pow(block_int, key.e, key.m)
            if encrypted_int == 0: num_16bit_digits_crypt = 1 
            else: num_16bit_digits_crypt = (encrypted_int.bit_length() + 15) // 16
            expected_hex_len = num_16bit_digits_crypt * 4 
            hex_text = format(encrypted_int, f'0{expected_hex_len}x') 
            result_parts.append(hex_text)
        if not result_parts: return ""
        return " ".join(result_parts)

    @staticmethod
    def encrypt_password(password: str, exponent: str, modulus: str) -> str:
        """
        公开方法：使用公钥加密密码。
        
        参数:
            password (str): 原始密码.
            exponent (str): RSA 公钥的 exponent (16进制).
            modulus (str): RSA 公钥的 modulus (16进制).
        
        返回:
            str: 加密并反转后的密码字符串.
        """
        key_obj = ZjuRSA._create_rsa_key(public_exponent_hex=exponent, modulus_hex=modulus)
        reversed_password = password[::-1] 
        encrypted_password = ZjuRSA._encrypted_string(key=key_obj, s=reversed_password)
        return encrypted_password

# ----------------------------------------------------------------------
# 3. 认证客户端: ZjuLibClient (未修改)
# ----------------------------------------------------------------------
class ZjuLibClient:
    """
    浙大图书馆预约系统 (booking.lib.zju.edu.cn) 认证客户端。
    
    职责:
    1. 封装完整的 CAS -> PHPSESSID -> cas_token -> JWT Token 认证流程。
    2. 提供一个已认证的、可用于 API 调用的 httpx.AsyncClient 会话实例。
    
    使用方法:
    async with ZjuLibClient() as client:
        success = await client.authenticate("studentid", "password")
        if success:
            # client.session 现在已认证，可以传递给 API 封装类
            api = ZjuLibAPI(client.session)
            await api.list(...)
    """
    
    # CAS (统一身份认证) 相关 URL
    CAS_LOGIN_BASE_URL = "https://zjuam.zju.edu.cn/cas"
    CAS_PUBKEY_URL = f"{CAS_LOGIN_BASE_URL}/v2/getPubKey"
    
    # 图书馆预约系统 (目标服务) 相关 URL
    TARGET_BASE_URL = "https://booking.lib.zju.edu.cn"
    # 关键：CAS 的 service URL，用于验证 ticket 并设置 PHPSESSID (模拟 cas.txt)
    CAS_SERVICE_URL = f"{TARGET_BASE_URL}/api/cas/cas"
    # 关键：JWT 换取 URL (模拟 user.txt)
    GET_JWT_TOKEN_URL = f"{TARGET_BASE_URL}/api/cas/user"
    # H5 首页 (可选访问，用于模拟浏览器)
    H5_INDEX_URL = f"{TARGET_BASE_URL}/h5/"

    def __init__(self, trust_env=True):
        """
        初始化 httpx.AsyncClient 会话，并设置模拟浏览器的全局请求头。
        这些请求头在 CAS 认证及 ticket 验证时是必需的。
        """
        self._session = httpx.AsyncClient(trust_env=trust_env, follow_redirects=True)
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Upgrade-Insecure-Requests': '1',
            'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
        })
        
        self.studentid: Optional[str] = None
        self._password: Optional[str] = None
        self._final_cas_url: Optional[httpx.URL] = None # 用于存储 login() 后的最终 URL

    @property
    def session(self) -> httpx.AsyncClient:
        """暴露内部已认证的 httpx.AsyncClient 会话对象"""
        return self._session

    async def __aenter__(self):
        """支持 'async with' 语法"""
        return self
    
    async def __aexit__(self, exc_type, exc_value, exc_traceback):
        """在退出 'async with' 块时自动关闭 httpx.AsyncClient 会话"""
        await self._session.aclose()
        
    async def authenticate(self, studentid: str, password: str) -> bool:
        """
        执行完整的认证流程。
        
        参数:
            studentid (str): 学号
            password (str): 密码
            
        返回:
            bool: True 表示认证成功，self.session 已就绪。False 表示失败。
        """
        self.studentid = studentid
        self._password = password
        
        # 1. 执行 CAS 登录，获取 PHPSESSID 和 cas_token URL
        if not await self._login():
            logger.error("\n--- CAS 登录失败 ---")
            return False
            
        # 2. (可选) 访问 H5 首页，更全面地模拟浏览器行为
        await self._visit_h5_index()

        # 3. 换取 JWT Token
        jwt_token = await self._get_jwt_token()
        if not jwt_token:
            logger.error("未能成功获取到 JWT Token，无法进行后续 API 请求。")
            logger.critical("\n[!!! 认证失败 !!!]\n请检查账号密码、网络连接或确认认证流程是否再次变更。\n")
            return False
        
        # 4. 将 JWT Token 配置到 session 的全局请求头中，为 API 调用做准备
        self._configure_session_for_api(jwt_token)
        logger.info("\n--- 认证成功，客户端已准备就绪 ---")
        return True

    async def _login(self) -> bool:
        """
        私有方法：执行 CAS 登录 (模拟 cas.txt 流程)。
        此函数将获取 PHPSESSID 和包含 cas_token 的 URL。
        """
        logger.info("--- [步骤 1] 开始 CAS 登录流程 ---")
        self._session.cookies.clear()
        
        # 构造 CAS 登录触发 URL，service 参数必须是 /api/cas/cas
        service_encoded = urllib.parse.quote(self.CAS_SERVICE_URL, safe='')
        login_trigger_url = f"{self.CAS_LOGIN_BASE_URL}/login?service={service_encoded}"
        
        try: 
            # 1.1 访问登录页，获取 execution
            logger.info(f"1.1 访问目标网站以触发登录重定向")
            login_response = await self._session.get(url=login_trigger_url, timeout=10)
            
            # 1.2 获取 RSA 公钥
            logger.info(f"1.2 获取 RSA 公钥参数: {self.CAS_PUBKEY_URL}")
            pubkey_json_resp = await self._session.get(url=self.CAS_PUBKEY_URL, timeout=5)
            pubkey_json_resp.raise_for_status()
            
            data = pubkey_json_resp.json()
            exponent = data.get("exponent")
            modulus = data.get("modulus")

            if exponent is None or modulus is None:
                logger.error("错误: PubKey API 调用失败，未能获取到公钥参数！")
                return False

        except (HTTPStatusError, ConnectTimeout, ValueError, Exception) as e:
            logger.error(f"登录初始化失败: {e}", exc_info=False)
            return False
        
        # 1.3 加密密码
        try:
            logger.info("1.3 加密密码...")
            encrypted_password = ZjuRSA.encrypt_password(
                password=self._password, 
                exponent=exponent, 
                modulus=modulus
            )
        except ValueError as e:
            logger.error(f"错误: 密码值错误！发生在 RSA 加密时。{e}")
            return False

        # 1.4 获取 execution 动态口令
        execution = self._get_execution(response=login_response)
        if not execution:
            logger.error("错误: 未能从登录页面提取到 'execution' 动态口令。")
            return False

        # 1.5 构建 POST 表单
        logger.info("1.4 构建 POST 表单并发送登录请求...")
        form_data = {
            'username': self.studentid,
            'password': encrypted_password,
            'authcode': '',
            'execution': execution[0],
            '_eventId': 'submit'
        }

        # 1.6 发送 POST 登录请求
        try:
            post_url = login_response.url 
            
            # httpx 将自动处理所有 302 重定向:
            # 1. POST /cas/login
            # 2. 302 -> GET /api/cas/cas?ticket=... (设置 PHPSESSID)
            # 3. 302 -> GET /h5/index.html#/cas/?cas=... (返回 cas_token URL)
            response = await self._session.post(
                url=post_url, 
                data=form_data,
                follow_redirects=True, # 必须为 True
                timeout=10
            )
            response.raise_for_status()
            logger.debug(f"登录重定向后，会话 Cookie 状态: {self._session.cookies}")

        except (HTTPStatusError, Exception) as e:
            logger.error(f"发送登录请求时发生错误: {e}")
            return False

        # 1.7 检查登录结果
        if self.CAS_LOGIN_BASE_URL in str(response.url):
            logger.error("登录失败，可能是学号或密码不正确！")
            return False
        else:
            # 登录成功，保存最终的 URL，它包含 cas_token
            self._final_cas_url = response.url
            logger.info(f"登录并交换 Ticket 成功!")
            
            # 验证 PHPSESSID 是否已成功设置
            phpsessid = self._session.cookies.get("PHPSESSID", domain="booking.lib.zju.edu.cn")
            if phpsessid is None:
                logger.error("严重错误: 登录成功，但未能在 booking.lib.zju.edu.cn 域上设置 PHPSESSID。")
                return False
                
            logger.info("PHPSESSID 成功设置。")
            return True

    def _get_execution(self, response: httpx.Response) -> list:
        """私有方法：从 CAS 登录页面 HTML 中提取 'execution' 动态口令。"""        
        html = etree.HTML(response.text)
        xpath_pattern = r'//input[@name="execution"]/@value'
        return html.xpath(xpath_pattern)
        
    async def _visit_h5_index(self):
        """
        私有方法：(可选) 访问 H5 首页。
        这有助于更全面地模拟浏览器行为，但对认证流程非必需。
        """
        logger.info(f"\n--- [步骤 2] 访问 H5 首页 (会话已建立): {self.H5_INDEX_URL} ---")
        try:
            h5_response = await self._session.get(self.H5_INDEX_URL, timeout=10)
            h5_response.raise_for_status()
            logger.info("H5 首页访问成功。")
        except Exception as e:
            logger.warning(f"警告: 访问 H5 首页失败 (但不影响JWT获取)。{e}", exc_info=False)

    async def _get_jwt_token(self) -> Optional[str]:
        """
        私有方法：执行 JWT Token 换取 (模拟 user.txt 流程)。
        
        返回:
            str: "bearer <token>" 字符串，或 None。
        """
        logger.info(f"\n--- [步骤 3] 开始换取 JWT Token ---")
        
        # *** 3.1 注入 JWTUser Cookie (模拟 user.txt) ***
        if not self.studentid:
            logger.error("错误：无法获取 studentid，无法构造 JWTUser Cookie。")
            return None
            
        jwtuser_data = {
            "account": "",
            "id": "", 
            "tenant_id": 0 
        }
        json_str = json.dumps(jwtuser_data, separators=(',', ':'))
        self._session.cookies.set("JWTUser", json_str, domain="booking.lib.zju.edu.cn", path="/")
        logger.info(f"3.1 注入 JWTUser Cookie: JWTUser={json_str}")
        
        # *** 3.2 从 _login() 捕获的 URL 中提取 cas token ***
        logger.info(f"3.2 尝试从 login() 最终 URL 中解析 cas_token")
        
        cas_token = None
        try:
            if not self._final_cas_url:
                logger.error("错误: _final_cas_url 未设置。")
                return None

            logger.info(f"解析 URL")
            parsed_url = urllib.parse.urlparse(str(self._final_cas_url))
            
            # H5 路由的参数在 fragment (#) 中 (匹配 ...#/cas/?cas=...)
            fragment_query_str = ""
            if '?' in parsed_url.fragment:
                 fragment_query_str = parsed_url.fragment.split('?', 1)[1]
            
            query_str = parsed_url.query
            query_params = urllib.parse.parse_qs(fragment_query_str or query_str) 
            
            if 'cas' not in query_params or not query_params['cas']:
                logger.error(f"解析 cas token 失败。未在 URL fragment 中找到 cas 参数: {self._final_cas_url}")
                return None
                
            cas_token = query_params['cas'][0]
            logger.info(f"成功提取 cas_token")

        except Exception as e:
            logger.error(f"解析 cas_token 时发生错误: {e}", exc_info=True)
            return None

        # *** 3.3 POST /api/cas/user (使用 cas_token) ***
        logger.info(f"3.3 尝试获取 JWT Token (POST + cas_token): {self.GET_JWT_TOKEN_URL}")
        
        try:
            cas_payload = {"cas": cas_token} # 匹配 user.txt 的 payload

            # 匹配 user.txt 的 XHR (API) 请求头
            # 注意：这些头会临时覆盖 __init__ 中的全局浏览器头
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Content-Type': 'application/json',
                'Origin': self.TARGET_BASE_URL,
                'Referer': f"{self.TARGET_BASE_URL}/h5/index.html",
                'Sec-Fetch-Dest': 'empty', 
                'Sec-Fetch-Mode': 'cors',  
                'Sec-Fetch-Site': 'same-origin', 
                'X-Requested-With': 'XMLHttpRequest',
                'Upgrade-Insecure-Requests': None # API 调用不需要这个
            }
            headers = {k: v for k, v in headers.items() if v is not None}
            
            response = await self._session.post( 
                url=self.GET_JWT_TOKEN_URL, 
                timeout=10,
                json=cas_payload, 
                headers=headers
            )
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"JWT Token API 原始响应: {json.dumps(data, ensure_ascii=False)}")
            
            # 匹配 user.txt 的成功响应
            if data.get("code") == 1 and "member" in data and isinstance(data["member"], dict) and "token" in data["member"]:
                jwt_token = "bearer" + data["member"]["token"]
                logger.info("JWT Token 获取成功。")
                return jwt_token
            else:
                logger.error(f"获取 JWT Token 失败。API 响应: {json.dumps(data, ensure_ascii=False)}")
                return None

        except (HTTPStatusError, ConnectTimeout, Exception) as e:
            logger.error(f"获取 JWT Token 时发生错误: {e}", exc_info=True)
            return None

    def _configure_session_for_api(self, jwt_token: str):
        """
        私有方法：将最终的 JWT Token 和 API 请求头设置到全局 session 中。
        """
        logger.info("\n--- [步骤 4] 配置全局 Session 以用于 API 调用 ---")
        
        # 准备 API 请求头 (模拟 list.txt)
        # 这些头将用于所有后续的 API 调用
        api_headers = {
            'Authorization': jwt_token, 
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'lang': 'zh',
            'Accept': 'application/json, text/plain, */*', # 覆盖全局的 'text/html'
            'Origin': self.TARGET_BASE_URL,
            'Referer': f"{self.TARGET_BASE_URL}/h5/index.html",
            'Sec-Fetch-Dest': 'empty', 
            'Sec-Fetch-Mode': 'cors',  
            'Sec-Fetch-Site': 'same-origin', 
            'Upgrade-Insecure-Requests': None # 移除
        }
        api_headers = {k: v for k, v in api_headers.items() if v is not None}
        
        # 更新 session 的全局 headers
        self._session.headers.update(api_headers)
        logger.info("Session 已更新，Authorization 和 API 请求头已设置。")


# ----------------------------------------------------------------------
# 4. 业务 API 封装: ZjuLibAPI (未修改)
# ----------------------------------------------------------------------
class ZjuLibAPI:
    """
    封装浙大图书馆预约系统的所有业务 API。
    
    职责:
    1. 接收一个已认证的 httpx.AsyncClient 实例。
    2. 提供简单的方法来调用具体的业务 API (如 list, get_seats, book_seat 等)。
    """
    
    # API URL 列表
    BASE_URL = "https://booking.lib.zju.edu.cn"
    LIST_AREAS_URL = f"{BASE_URL}/reserve/index/list" #
    GET_SEATS_URL = f"{BASE_URL}/api/Seat/seat"       #
    BOOK_SEAT_URL = f"{BASE_URL}/api/Seat/confirm"  #
    GET_SEGMENT_ID_URL = f"{BASE_URL}/api/Seat/date"  # 新增获取segment_id的API
    # ... 其他 API ...

    def __init__(self, session: httpx.AsyncClient):
        """
        使用一个已经通过 ZjuLibClient 认证的 httpx.AsyncClient 实例来初始化。
        
        参数:
            session (httpx.AsyncClient): 来自 ZjuLibClient.session
        """
        if 'Authorization' not in session.headers:
            logger.warning("传入的 session A'Authorization' 请求头，请确保已认证。")
            
        self._session = session
        # 从 session 中提取 JWT Token，用于 payload (如果 API 需要)
        self._jwt_token = session.headers.get('Authorization', '')

    async def list(self, 
                         date: str, 
                         category_id: str = "1", 
                         page: int = 1, 
                         size: int = 10
                         ) -> Optional[Dict[str, Any]]:
        """
        调用“获取场馆区域列表” API (list)
        
        参数:
            date (str): 查询日期, 格式 "YYYY-MM-DD".
            category_id (str): 分类 ID, 默认为 "1".
            page (int): 页码.
            size (int): 每页数量.
            
        返回:
            dict: API 返回的 JSON 数据，或 None。
        """
        logger.debug(f"\n--- C正在请求 API: 区域列表 (日期: {date}, 页码: {page}) ---")
        
        # 构造 Payload (匹配 list.txt 抓包文件)
        # 注意：authorization 字段在 payload 和 header 中同时存在
        api_payload = {
            "id": category_id,
            "date": date, 
            "categoryIds": [category_id],
            "members": 0,
            "size": size,
            "page": page,
            "authorization": self._jwt_token #  payload 中也需要 token
        }

        try:
            response = await self._session.post(
                self.LIST_AREAS_URL, 
                json=api_payload, 
                timeout=15
            )
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"API (list) 返回: {json.dumps(data, ensure_ascii=False)}")
            return data
            
        except HTTPStatusError as e:
            logger.error(f"请求 API (list) 失败，状态码: {e.response.status_code}")
            logger.debug(f"响应内容 (前200字): {e.response.text[:200]}...")
            return None
        except ConnectTimeout:
            logger.error("请求 API (list) 超时。")
            return None
        except Exception as e:
            logger.error(f"请求 API (list) 时发生未知错误: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # [新增] API 方法 (根据
    # ------------------------------------------------------------------
    
    async def get_seats(self, 
                        area_id: str, 
                        segment_id: str, 
                        date: str, 
                        start_time: str = "00:01", 
                        end_time: str = "23:59"
                        ) -> Optional[Dict[str, Any]]:
        """
        调用“获取区域座位列表” API (seat)
        (根据
        """
        logger.info(f"\n--- G正在请求 API: 座位列表 (区域ID: {area_id}, 日期: {date}, Segment: {segment_id}) ---")
        
        # 构造 Payload (根据
        api_payload = {
            "area": str(area_id),
            "segment": str(segment_id),
            "day": date,
            "startTime": start_time,
            "endTime": end_time,
            "authorization": self._jwt_token
        }

        try:
            response = await self._session.post(
                self.GET_SEATS_URL, 
                json=api_payload, 
                timeout=15
            )
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"API (get_seats) 响应: {json.dumps(data, ensure_ascii=False)}")
            
            if data.get("code") == 1: #
                logger.info(f"成功获取到 {len(data.get('data', []))} 个座位信息。")
            else:
                logger.warning(f"获取座位列表失败 (API code != 1): {data.get('msg')}")
            
            return data
            
        except HTTPStatusError as e:
            logger.error(f"请求 API (get_seats) 失败，状态码: {e.response.status_code}")
            return None
        except ConnectTimeout:
            logger.error("请求 API (get_seats) 超时。")
            return None
        except Exception as e:
            logger.error(f"请求 API (get_seats) 时发生未知错误: {e}", exc_info=True)
            return None

    async def book_seat(self,
                        seat_id: str,
                        segment_id: str
                        ) -> Optional[Dict[str, Any]]:
        """
        调用“确认预约座位” API (confirm)
        (根据
        """
        logger.info(f"\n--- 正在请求 API: 预约座位 (SeatID: {seat_id}, SegmentID: {segment_id}) ---")

        # 1. 获取加密 payload
        try:
            # 调用本文件顶部的 get_encrypted_seat_request 函数
            encrypted_payload = get_encrypted_seat_request(str(seat_id), str(segment_id))
        except Exception as e:
            logger.error(f"生成加密 payload 时出错: {e}", exc_info=True)
            return None

        # 2. 添加 authorization
        encrypted_payload['authorization'] = self._jwt_token

        logger.debug(f"API (book_seat) 发送的 Payload: {json.dumps(encrypted_payload)}")

        try:
            response = await self._session.post(
                self.BOOK_SEAT_URL,
                json=encrypted_payload,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()

            # 3. 根据响应打印日志
            if data.get("code") == 1: #
                logger.info(f"--- 预约成功 ---")
                logger.info(f"  消息: {data.get('msg')}")
                logger.info(f"  座位: {data.get('seat')}")
                logger.info(f"  时间: {data.get('new_time')}")
            else: #
                logger.warning(f"--- 预约失败 ---")
                logger.warning(f"  消息: {data.get('msg')}")

            return data

        except HTTPStatusError as e:
            logger.error(f"请求 API (book_seat) 失败，状态码: {e.response.status_code}")
            return None
        except ConnectTimeout:
            logger.error("请求 API (book_seat) 超时。")
            return None
        except Exception as e:
            logger.error(f"请求 API (book_seat) 时发生未知错误: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # [新增] API 方法 (获取segment_id)
    # ------------------------------------------------------------------

    async def get_segment_id(self,
                             build_id: str,
                             date: str
                             ) -> Optional[str]:
        """
        调用“获取segment_id” API (date)
        根据build_id和日期获取对应的segment_id

        参数:
            build_id (str): 区域的build_id.
            date (str): 查询日期, 格式 "YYYY-MM-DD".

        返回:
            str: 对应的segment_id，或 None。
        """
        logger.info(f"\n--- 正在请求 API: 获取segment_id (BuildID: {build_id}, 日期: {date}) ---")

        # 构造 Payload
        api_payload = {
            "build_id": str(build_id),
            "authorization": self._jwt_token
        }

        try:
            response = await self._session.post(
                self.GET_SEGMENT_ID_URL,
                json=api_payload,
                timeout=15
            )
            response.raise_for_status()

            data = response.json()
            logger.debug(f"API (get_segment_id) 响应: {json.dumps(data, ensure_ascii=False)}")

            # 解析响应获取segment_id
            if data.get("code") == 1 and "data" in data and len(data["data"]) > 0:
                segment_info = data["data"][0].get("times", [])
                if len(segment_info) > 0:
                    segment_id = segment_info[0].get("id")
                    logger.info(f"成功获取到segment_id: {segment_id}")
                    return segment_id

            logger.warning(f"获取segment_id失败: {data.get('msg')}")
            return None

        except HTTPStatusError as e:
            logger.error(f"请求 API (get_segment_id) 失败，状态码: {e.response.status_code}")
            return None
        except ConnectTimeout:
            logger.error("请求 API (get_segment_id) 超时。")
            return None
        except Exception as e:
            logger.error(f"请求 API (get_segment_id) 时发生未知错误: {e}", exc_info=True)
            return None


# ----------------------------------------------------------------------
# 5. 主程序业务逻辑
# ----------------------------------------------------------------------

# 5.1 策略常量 (修改)

# 定义区域名称到build_id的映射
BUILD_ID_MAP = {
    "二层南": "58",
    "二层北": "59",
    "三层东": "60",
    "三层南": "61",
    "三层北": "62",
    "四层东": "63",
    "四层南": "64",
    "四层西": "65",
    "四层北": "66",
    "五层东": "67"
}

# (预约优先级, 越靠前优先级越高)
# 策略: 二层北 > 二层南 > 三层 > 四层 > 五层
AREA_PRIORITY_LIST = [
    "二层北", "二层南",
    "三层东", "三层南", "三层北",
    "四层东", "四层南", "四层西", "四层北",
    "五层东"
]

# --- [模式 0 - 仅二层] ---
LIMITED_PRIORITY_LIST = [
    "二层北", "二层南",
]


# 5.2 辅助函数：获取所有分页的空闲区域 (已修改: 返回 Optional[list])
async def get_all_available_areas(api: ZjuLibAPI, date: str, build_id_map: dict) -> Optional[list]:
    """
    (修改) 获取 *第1页* 中 'free_num' > 0 且在 *指定* build_id_map 中定义的区域列表。

    返回:
        list: 成功且获取到列表（可能为空列表）。
        None: API 请求失败，暗示会话可能失效。
    """
    all_available_areas = []

    logger.info("--- 正在扫描区域列表第 1 页 (仅扫描第1页)... ---")
    list_data = await api.list(date=date, page=1, size=10) # 固定请求第1页

    # [修改点] 如果数据无效或 code != 0，返回 None 而不是 []
    if not list_data or list_data.get("code") != 0:
        logger.error(f"获取区域列表失败。API 响应: {list_data}")
        return None # 信号：会话可能已失效或 API 错误

    data_content = list_data.get("data", {})
    areas_on_page = data_content.get("list", [])

    if not areas_on_page:
        logger.info("第 1 页无区域数据。")
        return [] # 返回空列表，表示会话正常但无数据

    # 筛选有空座位的区域
    for area in areas_on_page:
        area_name = area.get('name')

        # 使用传入的 build_id_map 进行过滤
        if area.get("free_num", 0) > 0 and area_name in build_id_map:
            all_available_areas.append(area)

    return all_available_areas

# 5.3 主监控和预约逻辑 (已修改: 双层循环结构)
async def run_booking_logic(studentid: str, password: str, refresh_time: float, scope_mode: int):
    """
    运行主业务逻辑：登录、监控、抢座。
    (包含自动重连机制)
    """

    # 确保 lxml 已安装
    try:
        import lxml
    except ImportError:
        logger.error("错误: 缺少必要的库 lxml。请运行 pip3 install lxml")
        return

    # --- 根据 scope_mode 选择策略 ---
    active_priority_list: list
    area_filter_name: str

    if scope_mode == 0:
        logger.info("--- 运行模式: [0] 仅监控二层北/二层南 ---")
        active_priority_list = LIMITED_PRIORITY_LIST
        area_filter_name = "(主馆-仅二层)"
    else:
        logger.info("--- 运行模式: [1] 监控主馆所有区域 ---")
        active_priority_list = AREA_PRIORITY_LIST
        area_filter_name = "(主馆-全部)"

    def get_area_priority_internal(area: Dict[str, Any]) -> int:
        """辅助函数：获取排序的 key, 数字越小优先级越高。"""
        area_name = area.get('name', '')
        try:
            return active_priority_list.index(area_name)
        except ValueError:
            return 999

    # --- [修改点] 外层循环：负责会话重建 ---
    while True:
        logger.info("\n=== [系统] 启动新会话/准备重新认证 ===")

        # 使用 async with 管理 ZjuLibClient 的生命周期
        # 每次进入此块都会创建一个全新的 Client 实例 (清空 Cookies)
        async with ZjuLibClient(trust_env=True) as client:

            # 1. 认证
            success = await client.authenticate(studentid, password)

            if not success:
                logger.error("认证失败。将在 5 秒后重试...")
                await asyncio.sleep(5)
                continue # 重新开始外层循环

            # 2. 认证成功
            api = ZjuLibAPI(client.session)

            # 3. 内层循环：监控循环 (在当前 Session 有效时运行)
            logger.info(f"\n--- [步骤 5] 认证成功，开始监控{area_filter_name}空余座位 (刷新间隔: {refresh_time}s) ---")

            session_valid = True

            while session_valid:
                try:
                    # 3.1 获取当前日期
                    current_date_obj = date.today()
                    today_str = current_date_obj.strftime("%Y-%m-%d")

                    logger.info(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 当前日期: {today_str}")

                    # 3.2 获取所有(目标范围的)有空座位的区域
                    # 注意：这里我们传入BUILD_ID_MAP作为segment_map参数，因为get_all_available_areas函数需要它来过滤区域
                    # Use filtered build_id_map based on scope_mode
                    area_filter_map = BUILD_ID_MAP if scope_mode == 1 else {k: v for k, v in BUILD_ID_MAP.items() if k in LIMITED_PRIORITY_LIST}
                    available_areas = await get_all_available_areas(api, today_str, area_filter_map)

                    # [修改点] 检查是否发生致命错误 (Session 失效)
                    if available_areas is None:
                        logger.warning("检测到 API 返回异常 (返回 None)，判定当前会话已失效。")
                        logger.warning("正在中断当前监控循环，准备重启会话...")
                        session_valid = False
                        break # 跳出内层循环 -> 退出 async with -> 触发外层循环重启

                    if not available_areas:
                        # 只是没空位，Session 正常
                        logger.info(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] 未发现{area_filter_name}空余座位。 {refresh_time} 秒后重试...")
                        await asyncio.sleep(refresh_time)
                        continue

                    # 3.3 按照优先级排序
                    available_areas.sort(key=get_area_priority_internal)

                    logger.info(f"发现 {len(available_areas)} 个{area_filter_name}有空座位的区域，已按优先级排序:")
                    for i, area in enumerate(available_areas):
                        logger.info(f"  {i+1}. {area.get('name')} (空位数: {area.get('free_num')})")

                    # 3.4 遍历高优先级区域，尝试预约
                    for area in available_areas:
                        area_id = area.get("id")
                        area_name = area.get("name")

                        # 获取区域对应的build_id
                        build_id = BUILD_ID_MAP.get(area_name)
                        if not build_id:
                            logger.warning(f"未找到区域 {area_name} 对应的build_id，跳过该区域")
                            continue

                        # 动态获取segment_id
                        segment_id = await api.get_segment_id(build_id, today_str)
                        if not segment_id:
                            logger.warning(f"无法获取区域 {area_name} 的segment_id，尝试下一个区域")
                            continue

                        logger.info(f"\n--- 正在检查高优先级区域: {area_name} (ID: {area_id}) ---")

                        # 3.5 获取该区域的详细座位列表
                        seats_data = await api.get_seats(area_id, str(segment_id), today_str)

                        if not seats_data or seats_data.get('code') != 1:
                            # 如果 get_seats 也失败，可能也是 session 问题，但为了稳健，先视为区域错误，除非频繁发生
                            # 也可以在这里增加 session check 逻辑，但暂且依靠 list 接口做主 check
                            logger.warning(f"获取 {area_name} 的座位列表失败，尝试下一个区域。")
                            continue

                        all_seats = seats_data.get('data', [])
                        if not all_seats:
                            continue

                        # 3.6 查找第一个空闲座位
                        target_seat = None
                        for seat in all_seats:
                            if seat.get('status') == '1': # '1' = 空闲
                                target_seat = seat
                                break

                        # 3.7 找到空位，发起预约
                        if not target_seat:
                            continue

                        seat_id_to_book = target_seat.get('id')
                        seat_no = target_seat.get('no')
                        logger.info(f"在 {area_name} 找到空闲座位: {seat_no} (ID: {seat_id_to_book})，尝试预约...")

                        book_result = await api.book_seat(str(seat_id_to_book), str(segment_id))

                        if book_result and book_result.get('code') == 1:
                            logger.info(f"\n--- !!! 预约成功，程序退出 !!! ---")
                            return # 彻底结束程序
                        else:
                            msg = book_result.get('msg') if book_result else "未知错误"
                            logger.warning(f"预约 {seat_no} 失败: {msg}")
                            if "不可重复预约" in (msg or ""):
                                logger.info("检测到已有预约，程序退出。")
                                return

                    # 3.8 如果所有区域都尝试失败了
                    logger.info(f"已尝试所有发现的空闲区域，但均未成功。 {refresh_time} 秒后重新扫描...")
                    await asyncio.sleep(refresh_time)

                except Exception as e:
                    logger.error(f"监控循环中发生意外错误: {e}", exc_info=True)
                    # 如果发生未知异常，也最好重启一下会话，以防万一
                    logger.error("为安全起见，将重启会话。")
                    break # 跳出内层循环，触发外层重启

        # 外层循环末尾
        logger.info("旧会话已清理，准备重建...")
        await asyncio.sleep(3) # 给一点缓冲时间

def main():
    """主程序入口：解析命令行参数并启动 asyncio 循环。"""
    
    # [修改] 策略: python3 main.py <学号> <密码> [模式(0/1)] [刷新时间(秒)]
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        print("错误: 参数不足。")
        # [修改] 更新帮助文本
        print("用法: python3 main.py <学号> <密码> [模式, 0=仅二层, 1=全部, 默认0] [刷新间隔秒数, 默认1.0]")
        logger.error("用法: python3 main.py <学号> <密码> [模式, 0=仅二层, 1=全部, 默认0] [刷新间隔秒数, 默认1.0]")
        sys.exit(1)

    studentid = sys.argv[1]
    password = sys.argv[2]
    
    # [修改] 颠倒默认值和解析的顺序
    scope_mode = 0 # 默认 0 (仅二层)
    refresh_time = 1.0 # 默认 1 秒
    
    # [修改] 解析第 4 个参数 (模式, sys.argv[3])
    if len(sys.argv) >= 4:
        try:
            scope_mode = int(sys.argv[3]) # <--- [修正] 模式现在是 argv[3]
            if scope_mode not in [0, 1]:
                logger.warning(f"模式 (第4个参数 '{sys.argv[3]}') 必须是 0 或 1，已重置为 0。")
                scope_mode = 0
        except ValueError:
            logger.error(f"错误: 模式 (第4个参数 '{sys.argv[3]}') 必须是一个数字 (0 或 1)。")
            sys.exit(1)

    # [修改] 解析第 5 个参数 (刷新时间, sys.argv[4])
    if len(sys.argv) == 5:
        try:
            refresh_time = float(sys.argv[4]) # <--- [修正] 刷新时间现在是 argv[4]
            if refresh_time <= 0:
                logger.warning("刷新时间必须大于0，已重置为 1.0 秒。")
                refresh_time = 1.0
        except ValueError:
            logger.error(f"错误: 刷新时间 (第5个参数 '{sys.argv[4]}') 必须是一个数字 (例如 0.5 或 2)。")
            sys.exit(1)
    
    logger.info(f"--- 启动预约程序 ---")
    logger.info(f"  刷新间隔: {refresh_time} 秒")
    logger.info(f"  预约模式: {scope_mode} ({'仅二层' if scope_mode == 0 else '全部区域'})")
    
    try:
        # 启动主业务逻辑
        # [修改] 传入 scope_mode
        asyncio.run(run_booking_logic(studentid, password, refresh_time, scope_mode))
    except KeyboardInterrupt:
        logger.info("\n--- 用户手动中断程序 ---")
    except Exception as e:
        logger.critical(f"程序运行错误: {e}", exc_info=True)

if __name__ == "__main__":
    # 设置日志级别为 DEBUG 以查看详细的网络请求
    # 如果在 Github Workflow 中运行，可以设置为 INFO 减少日志量
    logging.getLogger().setLevel(logging.INFO) # [修改] 默认级别设为 INFO
    
    # 将 httpx 的日志级别调高，避免过多的 DEBUG 输出
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # 如果需要最详细的日志，取消注释下一行
    # logging.getLogger().setLevel(logging.DEBUG) 

    main()
