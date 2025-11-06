import asyncio
import json
import sys
import logging
from pathlib import Path
from datetime import date 
import io
import urllib.parse # 确保导入
from typing import Optional, Dict, Any


# 导入必要的库
import httpx
from httpx import HTTPStatusError, ConnectTimeout
from lxml import etree
import traceback
#输入seat_id和segment,输出confirmAPI所需的aesjson值
import json
import base64
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# 1. 从 JavaScript 代码中获取的硬编码 IV
HARDCODED_IV = "ZZWBKJ_ZHIHUAWEI"

def generate_dynamic_key() -> str:
    """
    (修正版) 根据你的逆向分析，生成动态加密密钥 Key。
    
    修正逻辑：
    规则: [YYYYMMDD] + [reverse(YYYYMMDD)]
    这会产生一个 16 字节的 Key。
    """
    # 1. 获取本地日期的 YYYYMMDD 字符串
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    
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
    """
    
    # 1. 自动生成 16 字节的动态 Key
    dynamic_key = generate_dynamic_key()
    print(f"[*] Generated Dynamic Key: {dynamic_key} (Length: {len(dynamic_key)})")
    print(f"[*]          Hardcoded IV: {HARDCODED_IV} (Length: {len(HARDCODED_IV)})")

    # 2. 构建明文 payload
    payload = {
        "seat_id": str(seat_id),
        "segment": str(segment)
    }

    # 3. 将 payload 转换为紧凑的 JSON 字符串
    plaintext_json = json.dumps(payload, separators=(',', ':'))
    print(f"[*] Plaintext JSON: {plaintext_json}")

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
# 3. 认证客户端: ZjuLibClient (重构)
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
            await api.list_areas(...)
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
            logger.info(f"1.1 访问目标网站以触发登录重定向: {login_trigger_url}")
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
            logger.info(f"登录并交换 Ticket 成功！最终重定向到: {self._final_cas_url}")
            
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
            "account": self.studentid,
            "id": self.studentid, 
            "tenant_id": 112 
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

            logger.info(f"解析 URL: {self._final_cas_url}")
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
            logger.info(f"成功提取 cas_token: {cas_token}")

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
# 4. 业务 API 封装: ZjuLibAPI (新增)
# ----------------------------------------------------------------------
class ZjuLibAPI:
    """
    封装浙大图书馆预约系统的所有业务 API。
    
    职责:
    1. 接收一个已认证的 httpx.AsyncClient 实例。
    2. 提供简单的方法来调用具体的业务 API (如 list, book 等)。
    
    扩展:
    未来如需添加“预约座位”功能，只需在此类中新增一个
    'async def book_seat(self, ...)' 方法即可。
    """
    
    # API URL 列表
    BASE_URL = "https://booking.lib.zju.edu.cn"
    LIST_AREAS_URL = f"{BASE_URL}/reserve/index/list"
    # BOOK_SEAT_URL = f"{BASE_URL}/reserve/ajax/reserve" # 示例：未来可添加
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
        调用“获取场馆区域列表” API 
        
        参数:
            date (str): 查询日期, 格式 "YYYY-MM-DD".
            category_id (str): 分类 ID, 默认为 "1".
            page (int): 页码.
            size (int): 每页数量.
            
        返回:
            dict: API 返回的 JSON 数据，或 None。
        """
        logger.info(f"\n--- 正在请求 API: 区域列表 (日期: {date}, 页码: {page}) ---")
        
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
            logger.info("\n--- API (list_areas) 返回的 JSON 内容 ---")
            logger.info(json.dumps(data, indent=4, ensure_ascii=False))
            logger.info("--------------------------")
            return data
            
        except HTTPStatusError as e:
            logger.error(f"请求 API (list_areas) 失败，状态码: {e.response.status_code}")
            logger.debug(f"响应内容 (前200字): {e.response.text[:200]}...")
            return None
        except ConnectTimeout:
            logger.error("请求 API (list_areas) 超时。")
            return None
        except Exception as e:
            logger.error(f"请求 API (list_areas) 时发生未知错误: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # TODO: 在此添加更多 API 方法
    # ------------------------------------------------------------------
    # async def book_seat(self, seat_id: str, start_time: str, end_time: str):
    #    """
    #    示例：预约座位的 API。
    #    """
    #    logger.info(f"--- 正在请求 API: 预约座位 {seat_id} ---")
    #    payload = { ... }
    #    response = await self._session.post(self.BOOK_SEAT_URL, json=payload)
    #    return response.json()
    # ------------------------------------------------------------------


# ----------------------------------------------------------------------
# 5. 主程序入口 (重构)
# ----------------------------------------------------------------------
async def run_example(studentid: str, password: str):
    """
    运行一个示例，演示登录并调用“获取区域列表”API。
    """
    
    # 确保 lxml 已安装
    try:
        import lxml
    except ImportError:
        logger.error("错误: 缺少必要的库 lxml。请运行 pip3 install lxml")
        return

    # 使用 async with 管理 ZjuLibClient 的生命周期
    async with ZjuLibClient(trust_env=True) as client:
        
        # 1. 认证
        # 成功后，client.session 将包含所有必要的 Cookie 和 Auth Header
        success = await client.authenticate(studentid, password)
        
        if not success:
            logger.error("认证失败，程序退出。")
            return

        # 2. 认证成功，创建一个 API 封装实例
        # 将已认证的 client.session 传递给它
        api = ZjuLibAPI(client.session)
        
        # 3. 调用具体的 API
        today_str = date.today().strftime("%Y-%m-%d")
        areas_data = await api.list(date=today_str)
        
        if areas_data and areas_data.get("code") == 0:
            logger.info(f"成功获取到 {len(areas_data.get('data', {}).get('list', []))} 个区域。")
            
            # 示例：获取第二页
            # logger.info("\n--- 示例：获取第二页 ---")
            # await api.list_areas(date=today_str, page=2)

        # 4. 未来可在此处调用其他 API
        # logger.info("\n--- 未来可在此处调用预约API ---")
        # await api.book_seat(...)

def main():
    """主程序入口：解析命令行参数并启动 asyncio 循环。"""
    
    if len(sys.argv) != 3:
        logger.error("用法: python3 2.py <学号> <密码>")
        sys.exit(1)

    studentid = sys.argv[1]
    password = sys.argv[2]
    
    try:
        asyncio.run(run_example(studentid, password))
    except Exception as e:
        logger.critical(f"程序运行错误: {e}", exc_info=True)

if __name__ == "__main__":
    # 设置日志级别为 DEBUG 以查看详细的网络请求
    logging.getLogger().setLevel(logging.DEBUG) 
    
    # 将 httpx 的日志级别调高，避免过多的 DEBUG 输出
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    main()