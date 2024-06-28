#2024-06-28 15:34:54

import os
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
import urllib.parse
import time


# 加密密码
def jm(password):
    public_key_base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD6XO7e9YeAOs+cFqwa7ETJ+WXizPqQeXv68i5vqw9pFREsrqiBTRcg7wB0RIp3rJkDpaeVJLsZqYm5TW7FWx/iOiXFc+zCPvaKZric2dXCw27EvlH5rq+zwIPDAJHGAfnn1nmQH7wR3PCatEIb8pz5GFlTHMlluw4ZYmnOwg+thwIDAQAB"
    public_key_der = base64.b64decode(public_key_base64)
    key = RSA.importKey(public_key_der)
    cipher = PKCS1_v1_5.new(key)
    password_bytes = password.encode('utf-8')
    encrypted_password = cipher.encrypt(password_bytes)
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
    url_encoded_data = urllib.parse.quote(encrypted_password_base64)
    return url_encoded_data


# 签名并获取认证码
def sign(phone, password):
    url_encoded_data = jm(password)
    url = "https://passport.tmuyun.com/web/oauth/credential_auth"
    payload = f"client_id=10019&password={url_encoded_data}&phone_number={phone}"
    headers = {
        'User-Agent': "ANDROID;13;10019;6.0.2;1.0;null;MEIZU 20",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Cache-Control': "no-cache",
        'X-SIGNATURE': "185d21c6f3e9ec4af43e0065079b8eb7f1bb054134481e57926fcc45e304b896",
    }

    response = requests.post(url, data=payload, headers=headers)
    try:
        code = response.json()['data']['authorization_code']['code']
        url = "https://vapp.taizhou.com.cn/api/zbtxz/login"
        payload = f"check_token=&code={code}&token=&type=-1&union_id="
        headers = {
            'User-Agent': "6.0.2;00000000-67e9-2a58-0000-000010724a65;Meizu MEIZU 20;Android;13;tencent;6.10.0",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-SESSION-ID': "66586b383f293a7173e4c8f4",
            'X-REQUEST-ID': "110c1987-1637-4f4e-953e-e35272bb891e",
            'X-TIMESTAMP': "1717072109065",
            'X-SIGNATURE': "a69f171e284594a5ecc4baa1b2299c99167532b9795122bae308f27592e94381",
            'X-TENANT-ID': "64",
            'Cache-Control': "no-cache"
        }
        response = requests.post(url, data=payload, headers=headers)
        message = response.json()['message']
        account_id = response.json()['data']['account']['id']
        session_id = response.json()['data']['session']['id']
        name = response.json()['data']['account']['nick_name']
        return message, account_id, session_id, name
    except Exception:
        print('出错啦！')
        return None, None, None, None


# 登录并获取 JSESSIONID
def login(account_id, session_id, retry_count=3):
    base_url = 'https://srv-app.taizhou.com.cn'
    url = f'{base_url}/tzrb/user/loginWC'
    headers = {
        'Host': 'srv-app.taizhou.com.cn',
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Pro Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36;xsb_wangchao;xsb_wangchao;5.3.1;native_app',
        'Accept': '*/*',
        'X-Requested-With': 'com.shangc.tiennews.taizhou',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://srv-app.taizhou.com.cn/luckdraw/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'
    }
    params = {
        'accountId': account_id,
        'sessionId': session_id
    }

    # 创建一个包含重试策略的会话
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))

    for attempt in range(retry_count):
        try:
            response = session.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                cookies_dict = response.cookies.get_dict()
                s_JSESSIONID = '; '.join([f'{k}={v}' for k, v in cookies_dict.items()])
                return s_JSESSIONID
            else:
                print(f"请求失败，状态码: {response.status_code}, 响应内容: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"请求失败 (尝试 {attempt + 1}/{retry_count}): {e}")
            time.sleep(2)  # 在重试前增加延迟

    return None


def cj(jsessionid, retry_count=3):
    url = "https://srv-app.taizhou.com.cn/tzrb/userAwardRecordUpgrade/saveUpdate"
    payload = "activityId=67&sessionId=undefined&sig=undefined&token=undefined"
    headers = {
        'Host': 'srv-app.taizhou.com.cn',
        'Connection': 'keep-alive',
        'Content-Length': '63',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; MI 8 Build/QKQ1.190828.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.101 Mobile Safari/537.36;xsb_wangchao;xsb_wangchao;6.0.2;native_app;6.10.0',
        'Content-type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'Origin': 'https://srv-app.taizhou.com.cn',
        'X-Requested-With': 'com.shangc.tiennews.taizhou',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://srv-app.taizhou.com.cn/luckdraw-ra-1/',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': f'{jsessionid}'
    }

    # 创建一个包含重试策略的会话
    session = requests.Session()
    retries = Retry(total=4, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))

    for attempt in range(retry_count):
        try:
            response = session.post(url, data=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                print(response.text)
                return  # 成功则退出函数
            else:
                print(f"POST 请求失败，状态码: {response.status_code}, 响应内容: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"POST 请求失败 (尝试 {attempt + 1}/{retry_count}): {e}")
            time.sleep(2)  # 在重试前增加延迟


# 从环境变量中读取账户和密码
accounts = os.getenv("wangchaoAccount")

if not accounts:
    print("❌未找到环境变量！")
else:
    accounts_list = accounts.split("&")
    print("=====By夜神月=====")
    print(f"一共在环境变量中获取到 {len(accounts_list)} 个账号")
    for account in accounts_list:
        phone, password = account.split("#")
        message, account_id, session_id, name = sign(phone, password)
        if account_id and session_id:
            mobile = phone[:3] + "*" * 4 + phone[7:]
            print(f"账号 {mobile} 登录成功")
            jsessionid = login(account_id, session_id)
            if jsessionid:
                cj(jsessionid)
            else:
                print(f"获取 JSESSIONID 失败")
        else:
            print(f"账号 {phone} 登录失败")

        # 每个账号登录后延迟...
        print("等待 5 秒后继续下一个账号...")
        time.sleep(5)
