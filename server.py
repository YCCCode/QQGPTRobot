from __future__ import annotations 

import argparse  # 导入解析命令行参数的模块。
import asyncio
import json
import os
import random
import ssl
import uuid #导入处理 UUID（通用唯一识别码）的模块。
from enum import Enum #导入定义枚举的模块。
from typing import Generator #导入定义生成器的类型提示。
from typing import Literal #导入定义字面量类型的类型提示。
from typing import Optional #导入定义可选参数的类型提示。
from typing import Union #导入定义联合类型的类型提示。

import certifi
import httpx
import websockets.client as websockets
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from rich.live import Live
from rich.markdown import Markdown

import socket
import threading
import requests
import re
import sys
import sqlite3
import datetime

isAskBing:bool
BingCount:int = 0


chatMAX = 70
TEST = 0

DELIMITER = "\x1e"
COOKIE_FILE =os.path.dirname(os.path.realpath(__file__))  +"/cookie.json"
DATABASE_FILE =os.path.dirname(os.path.realpath(__file__))  + '/qqbot.db'
bot =None

# Generate random IP between range 13.104.0.0/14
FORWARDED_IP = (
    f"13.{random.randint(104, 107)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
)

HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "sec-ch-ua": '"Not_A Brand";v="99", "Microsoft Edge";v="110", "Chromium";v="110"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version": '"109.0.1518.78"',
    "sec-ch-ua-full-version-list": '"Chromium";v="110.0.5481.192", "Not A(Brand";v="24.0.0.0", "Microsoft Edge";v="110.0.1587.69"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": "",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"15.0.0"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "x-ms-client-request-id": str(uuid.uuid4()),
    "x-ms-useragent": "azsdk-js-api-client-factory/1.0.0-beta.1 core-rest-pipeline/1.10.0 OS/Win32",
    "Referer": "https://www.bing.com/search?q=Bing+AI&showconv=1&FORM=hpcodx",
    "Referrer-Policy": "origin-when-cross-origin",
    "x-forwarded-for": FORWARDED_IP,
}

HEADERS_INIT_CONVER = {
    "authority": "edgeservices.bing.com",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "max-age=0",
    "sec-ch-ua": '"Chromium";v="110", "Not A(Brand";v="24", "Microsoft Edge";v="110"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version": '"110.0.1587.69"',
    "sec-ch-ua-full-version-list": '"Chromium";v="110.0.5481.192", "Not A(Brand";v="24.0.0.0", "Microsoft Edge";v="110.0.1587.69"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"15.0.0"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69",
    "x-edge-shopping-flag": "1",
    "x-forwarded-for": FORWARDED_IP,
}

ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations(certifi.where())



class NotAllowedToAccess(Exception):
    print(f"86:{Exception}")
    pass


class ConversationStyle(Enum):
    creative = "h3relaxedimg"
    balanced = "galileo"
    precise = "h3precise"


CONVERSATION_STYLE_TYPE = Optional[
    Union[ConversationStyle, Literal["creative", "balanced", "precise"]]
]


def append_identifier(msg: dict) -> str:
    """
    把字符添加到消息末尾
    """
    # Convert dict to json string
    return json.dumps(msg) + DELIMITER


def get_ran_hex(length: int = 32) -> str:
    """
    返回随机16进制文本
    """
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


class ChatHubRequest:
    """
    返回 object for ChatHub
    """

    def __init__(
        self,
        conversation_signature: str,
        client_id: str,
        conversation_id: str,
        invocation_id: int = 0,
    ) -> None:
        self.struct: dict = {}

        self.client_id: str = client_id
        self.conversation_id: str = conversation_id
        self.conversation_signature: str = conversation_signature
        self.invocation_id: int = invocation_id

    def update(
        self,
        prompt: str,
        conversation_style: CONVERSATION_STYLE_TYPE,
        options: list | None = None,
    ) -> None:
        """
        更新 request object
        """
        if options is None:
            options = [
                "deepleo",
                "enable_debug_commands",
                "disable_emoji_spoken_text",
                "enablemm",
            ]
        if conversation_style:
            if not isinstance(conversation_style, ConversationStyle):
                conversation_style = getattr(ConversationStyle, conversation_style)
            options = [
                "nlu_direct_response_filter",
                "deepleo",
                "disable_emoji_spoken_text",
                "responsible_ai_policy_235",
                "enablemm",
                conversation_style.value,
                "dtappid",
                "cricinfo",
                "cricinfov2",
                "dv3sugg",
            ]
        self.struct = {
            "arguments": [
                {
                    "source": "cib",
                    "optionsSets": options,
                    "sliceIds": [
                        "222dtappid",
                        "225cricinfo",
                        "224locals0",
                    ],
                    "traceId": get_ran_hex(32),
                    "isStartOfSession": self.invocation_id == 0,
                    "message": {
                        "author": "user",
                        "inputMethod": "Keyboard",
                        "text": prompt,
                        "messageType": "Chat",
                    },
                    "conversationSignature": self.conversation_signature,
                    "participant": {
                        "id": self.client_id,
                    },
                    "conversationId": self.conversation_id,
                },
            ],
            "invocationId": str(self.invocation_id),
            "target": "chat",
            "type": 4,
        }
        self.invocation_id += 1


class Conversation:
    """
    Conversation API
    """

    def __init__(
        self,
        cookiePath: str = "",
        cookies: dict | None = None,
        proxy: str | None = None,
    ) -> None:
        self.struct: dict = {
            "conversationId": None,
            "clientId": None,
            "conversationSignature": None,
            "result": {"value": "Success", "message": None},
        }
        self.session = httpx.Client(
            proxies=proxy,
            timeout=30,
            headers=HEADERS_INIT_CONVER,
        )
        if cookies is not None:
            cookie_file = cookies
        else:
            f = (
                open(cookiePath, encoding="utf8").read()
                if cookiePath
                else open(os.environ.get("COOKIE_FILE"), encoding="utf-8").read()
            )
            cookie_file = json.loads(f)
        for cookie in cookie_file:
            self.session.cookies.set(cookie["name"], cookie["value"])

        # Send GET request
        response = self.session.get(
            url=os.environ.get("BING_PROXY_URL")
            or "https://edgeservices.bing.com/edgesvc/turing/conversation/create",
        )
        if response.status_code != 200:
            response = self.session.get(
                "https://edge.churchless.tech/edgesvc/turing/conversation/create",
            )
        if response.status_code != 200:
            print(f"Status code: {response.status_code}")
            print(response.text)
            print(response.url)
            raise Exception("Authentication failed")
        try:
            self.struct = response.json()
        except (json.decoder.JSONDecodeError, NotAllowedToAccess) as exc:
            raise Exception(
                "Authentication failed. You have not been accepted into the beta.",
            ) from exc
        if self.struct["result"]["value"] == "UnauthorizedRequest":
            raise NotAllowedToAccess(self.struct["result"]["message"])


class ChatHub:

    def __init__(self, conversation: Conversation) -> None:
        self.wss: websockets.WebSocketClientProtocol | None = None
        self.request: ChatHubRequest
        self.loop: bool
        self.task: asyncio.Task
        self.request = ChatHubRequest(
            conversation_signature=conversation.struct["conversationSignature"],
            client_id=conversation.struct["clientId"],
            conversation_id=conversation.struct["conversationId"],
        )

    async def ask_stream(
        self,
        prompt: str,
        wss_link: str,
        conversation_style: CONVERSATION_STYLE_TYPE = None,
    ) -> Generator[str, None, None]:
        if self.wss==None:
            self.wss = await websockets.connect(
                    wss_link,
                    extra_headers=HEADERS,
                    max_size=None,
                    ssl=ssl_context,
                )
            await self.__initial_handshake()
        elif self.wss!=None:
            if(self.wss.closed==True):
                await self.wss.close()
                self.wss = await websockets.connect(
                        wss_link,
                        extra_headers=HEADERS,
                        max_size=None,
                        ssl=ssl_context,
                    )
                await self.__initial_handshake()
        # Construct a ChatHub request
        self.request.update(prompt=prompt, conversation_style=conversation_style)
        # Send request
        await self.wss.send(append_identifier(self.request.struct))
        final = False
        
        lastlen = 0
        while not final:
            
            
            try:
                objects = str(await self.wss.recv()).split(DELIMITER)
                for obj in objects:
                    if obj is None or not obj:
                        continue
                    response = json.loads(obj)
                    if response.get("type") == 1 and response["arguments"][0].get(
                        "messages",):
                        
                        resp_txt = response["arguments"][0]["messages"][0]["adaptiveCards"][0]["body"][0].get("text")

                        reply = resp_txt[lastlen:]
                        lastlen=len(resp_txt)
                        yield False,reply
                            
                    elif response.get("type") == 2:
                        final = True
                        yield True, response
            except Exception as res:
                    final = True
                    yield True, response

    async def __initial_handshake(self) -> None:
        await self.wss.send(append_identifier({"protocol": "json", "version": 1}))
        await self.wss.recv()

    async def close(self) -> None:
        """
        Close the connection
        """
        if self.wss and not self.wss.closed:
            await self.wss.close()


class Chatbot:

    def __init__(
        self,
        cookiePath: str = "",
        cookies: dict | None = None,
        proxy: str | None = None,
    ) -> None:
        self.cookiePath: str = cookiePath
        self.cookies: dict | None = cookies
        self.proxy: str | None = proxy
        self.chat_hub: ChatHub = ChatHub(
            Conversation(self.cookiePath, self.cookies, self.proxy),
        )

    async def ask_stream(
        self,
        prompt: str,
        wss_link: str = "wss://sydney.bing.com/sydney/ChatHub",
        conversation_style: CONVERSATION_STYLE_TYPE = None,
    ) -> Generator[str, None, None]:
        """
        Ask a question to the bot
        """
        async for response in self.chat_hub.ask_stream(
            prompt=prompt,
            conversation_style=conversation_style,
            wss_link=wss_link,
        ):
            yield response

    async def close(self) -> None:
        """
        Close the connection
        """
        await self.chat_hub.close()

    async def reset(self) -> None:
        """
        Reset the conversation
        """
        await self.close()
        self.chat_hub = ChatHub(Conversation(self.cookiePath, self.cookies))

def create_session() -> PromptSession:
    return PromptSession(history=InMemoryHistory())

async def AskBing(question:str,replyQQ:str) -> None:
    """
    Main function
    """
   
    global bot
    wrote = ""
    async for final, response in bot.ask_stream(
        prompt=question,
        conversation_style="balanced",
        wss_link="wss://sydney.bing.com/sydney/ChatHub",
    ):
        
        if not final:
            wrote+=response
            if(len(wrote)>50):
                
                SendMessage(replyQQ,wrote)
                wrote=""
        else:
            if(len(wrote)>0):
                SendMessage(replyQQ,wrote)
                wrote=""
    
    print("over")
    return




def SendMessage(qqnum,message):
    if TEST == 1:
        print(message)
        return
    
    LogChat("发送",qqnum,message)
    url = "http://127.0.0.1:5000/send_private_msg"
    data={
        "user_id":qqnum,
        "message":message
    } 
    requests.post(url=url,data=data,proxies=None)
    

def AskChatGPT(question:str,repQQ:str):
    askgpt_sider(repQQ=repQQ,question=question)
    
    return
    # 设置POST请求的头部和数据
    headers = {
        'Authorization': 'Bearer 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',
        'Content-Type': 'application/json'
    }
    data = {
        'model': 'gpt-3.5-turbo',
        'stream': True,
        'messages': [
            {
                'role': 'user',
                'content': question
            }
            # {
            #     'role': 'assistant',
            #     'content': '2'
            # },
            # {
            #     'role': 'user',
            #     'content': '用30个文字的给我科普一个知识点'
            # }
        ]
    }
    # 发送POST请求，并开始流式处理响应
    response = requests.post('https://api.openai.com/v1/chat/completions',headers=headers, json=data, stream=True)

    result =""
    for line in response.iter_lines():
        if line:
            # 将字节类型的数据转换为字符串类型
            data_str = line.decode('utf-8')

            # 去除"data: "前缀
            data_str = data_str.lstrip('data: ')
            
            # 判断数据是否完全是json格式
            if data_str.startswith('{') and data_str.endswith('}'):

                # 将字符串类型的数据转换为字典类型
                data_dict = json.loads(data_str)
                
                # 判断是否存在content键
                if 'content' in data_dict['choices'][0]['delta']:
                    # 提取content的值
                    content = data_dict['choices'][0]['delta']['content']
                    result += content
                    if(len(result)>150):
                        print(result)
                        SendMessage(repQQ,result)
                        result=""

    if(len(result)>0):
        SendMessage(repQQ,result)
        result=""

suderAuthIndex=0
siderAuth=[]
siderAuth.append("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyMDE1MzIzLCJyZWdpc3Rlcl90eXBlIjoicGhvbmUiLCJhcHBfbmFtZSI6IkNoaXRDaGF0X0VkZ2VfRXh0IiwidG9rZW5faWQiOiI0NGUwMGM4MC0xZWNmLTRkYmYtOTNmZC0zMTUwNzQ0NGZmZDQiLCJpc3MiOiJzaWRlci5haSIsImF1ZCI6WyIiXSwiZXhwIjoxNjk1MzA0MDI5LCJuYmYiOjE2ODc1MjgwMjksImlhdCI6MTY4NzUyODAyOX0.OWgCv5XzQSmGqpeOdUhGUZqx0M5SHxllBw4vjnaZGC4")
siderAuth.append('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxNjc3MDIsInJlZ2lzdGVyX3R5cGUiOiJwaG9uZSIsImFwcF9uYW1lIjoiQ2hpdENoYXRfV2ViIiwiaXNzIjoiZ29jaGl0Y2hhdC5haSIsImF1ZCI6WyIiXSwiZXhwIjoxNjgzNjA4MjA0LCJuYmYiOjE2ODEwMTYyMDQsImlhdCI6MTY4MTAxNjIwNH0.SZdkduJdjpm2nvxnXePuK-a2YJ_QN5dP8p23WGVcZCI')
siderAuth.append("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyMDE3Mjc4LCJyZWdpc3Rlcl90eXBlIjoib2F1dGgyIiwiYXBwX25hbWUiOiJDaGl0Q2hhdF9FZGdlX0V4dCIsInRva2VuX2lkIjoiNmM1OTAzODgtY2NhNi00NTA4LTg2YjYtOGRjMDVjNTQxZWM2IiwiaXNzIjoic2lkZXIuYWkiLCJhdWQiOlsiIl0sImV4cCI6MTY5NTMxMTgwMSwibmJmIjoxNjg3NTM1ODAxLCJpYXQiOjE2ODc1MzU4MDF9.GVZul4kC2CHUkfZNkQfDlahG8YWWrNpZccEU4C3vanQ")
last=0
sidercount = 0
def siderCheck():
    now = datetime.datetime.now().day
    global last,sidercount,suderAuthIndex
    if(last != now):
        suderAuthIndex = 0
    last = now
    
    if(sidercount>=29):
        suderAuthIndex+=1
        if(len(siderAuth)<=suderAuthIndex):
            #超过临界点
            
            return False
        sidercount=0
    sidercount+=1
    return True

def askgpt_sider(repQQ:str,question:str):
    global suderAuthIndex
    if siderCheck()==False:
        SendMessage(repQQ,"错误代码530;sc"+str(sidercount))
        return
    
    try:
        url = 'https://gochitchat.ai/api/v1/completion/text'

        # 设置请求头部信息
        headers = {
            'Content-Type': 'application/json',
            #'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxNjc3MDIsInJlZ2lzdGVyX3R5cGUiOiJwaG9uZSIsImFwcF9uYW1lIjoiQ2hpdENoYXRfV2ViIiwiaXNzIjoiZ29jaGl0Y2hhdC5haSIsImF1ZCI6WyIiXSwiZXhwIjoxNjgzNjA4MjA0LCJuYmYiOjE2ODEwMTYyMDQsImlhdCI6MTY4MTAxNjIwNH0.SZdkduJdjpm2nvxnXePuK-a2YJ_QN5dP8p23WGVcZCI'
            'Authorization':siderAuth[suderAuthIndex]
        }

        # 设置请求正文
        data = {
            'prompt': question+'\ncouldflare',
            'stream': True,
            'app_name': 'ChitChat_Edge_Ext',
            'app_version': '2.4.0',
            'tz_name': 'Asia/Hong_Kong',
            'cid': '',
            'model': 'gpt3.5',
            "from":"ask",
            "prompt_key":"custom"
        }

        response = requests.post(url, headers=headers, data=json.dumps(data)).content

            # 将字符串按照 \n\n 分割成多个 JSON 对象
        json_list = [s.strip()[5:] for s in response.decode().split('\n\n') if s.strip().startswith('data:')]


        json_list = json_list[1:len(json_list)-2]
        returnstr = ""
        for json1 in json_list:
            # 将字符串转换为 JSON 对象
            response_json = json.loads(json1)

            # 提取 text 值
            text_value = response_json['data']['text']

            returnstr = returnstr + text_value
            
        SendMessage(repQQ,returnstr)
    except Exception as res:
        LogChat("错误",'免费的ai',str(res.__traceback__.tb_lineno)+str(res))
        
        suderAuthIndex+=1
        askgpt_sider(repQQ,question)

# 定义一个线程本地存储对象来保存每个线程的SQLite对象
local = threading.local()

# 定义一个连接数据库的方法，每个线程都会调用该方法获取自己的SQLite对象
def get_db():
    # 如果线程本地存储对象中没有SQLite对象，则创建一个新的SQLite对象
    if not hasattr(local, 'db'):
        local.db = sqlite3.connect(DATABASE_FILE)
    return local.db

def checkDB(db_name,table_name):
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    sql = '''SELECT tbl_name FROM sqlite_master WHERE type = 'table' '''
    cur.execute(sql)
    values = cur.fetchall()
    tables = []
    cur.close()
    conn.close()
    for v in values:
        tables.append(v[0])
    if table_name not in tables:
        return False # 可以建表
    else:
        return True # 不能建表
    
#聊天记录
def LogChat(chatType:str,chatQQ:str,chatContent:str):
    print("chattype:"+chatType+",chatqq:"+str(chatQQ)+",chatcontent:"+str(chatContent))
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    
    if (checkDB("qqbot.db","chat") == False):
        sql_text_1 = '''CREATE TABLE chat
                (时间 TEXT,
                    类型 TEXT,
                        QQ TEXT,
                            内容 TEXT);'''
        print("执行sql语句")
        cur.execute(sql_text_1)


    now = datetime.datetime.now()

    cur.execute('INSERT INTO chat(时间,类型,QQ,内容) values(?,?,?,?)',(now.strftime("%Y-%m-%d %H:%M:%S"),chatType,chatQQ,chatContent) )

    cur.connection.commit()
    cur.close()
    conn.close()
#添加授权
def AddAuth(QQ:str):  
    
    if(CheckAuth(QQ)):
        return

    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    
    if (checkDB("qqbot.db","authQQ") == False):
        sql_text_1 = '''CREATE TABLE authQQ
                (QQ TEXT);'''
        print("执行sql语句")
        cur.execute(sql_text_1)


    now = datetime.datetime.now()

    cur.execute('INSERT INTO authQQ(QQ) values(?)',(QQ,))
    cur.connection.commit()
    cur.close()
    conn.close()
#检查授权
def CheckAuth(QQ:str):
    conn = sqlite3.connect(DATABASE_FILE)
    cur = conn.cursor()
    if (checkDB("qqbot.db","authQQ") == False):
        sql_text_1 = '''CREATE TABLE authQQ
                (QQ TEXT);'''
        print("执行sql语句")
        cur.execute(sql_text_1)


    cur.execute("SELECT QQ FROM authQQ WHERE QQ="+QQ+" ")
    result = cur.fetchone()
    cur.connection.commit()
    cur.close()
    conn.close()
    if result is None:
        return False
    else:
        return True

def handle(message:str,qqnum:str,query=0):
    global isAskBing
    global BingCount
    global bot
    LogChat("接收",qqnum,message)

    print("245消息处理:"+qqnum+"--"+message)
    global chatMAX

    if message=="在吗":
        SendMessage(qqnum,"在的~")
        return
    
    if message=="help":
        SendMessage(qqnum,"""
#1[消息]:采用chatgpt回答消息,基本不会产生拥堵,不支持连续对话,不能联网

#2[消息]:采用newbing回答消息,支持连续对话,并且会联网给出参考来源,但容易产生拥堵

例如发送:#2南昌明天的天气如何?

1号和2号各具特点,按需使用

如提示访问失败,请先获取机器人聊天授权:
    申请授权+[消息]:申请获得授权,将授权申请和消息一起发送给管理员
                    """)
        return
    

    
    if qqnum == "418802639": 
        chatMAX=chatMAX-1
       
        global suderAuthIndex
        if(message.find('回复')!=-1 and message.find(",")!=-1):  
            b=message.split(",")
            c=b[0].split("回复")
            SendMessage(c[1],b[1])
            SendMessage("418802639","回复成功")
            return
        elif(message.find("gindex")!=-1):
            SendMessage("418802639",suderAuthIndex)
            return
        elif(message.find('scount')!=-1):
            suderAuthIndex+=1
            SendMessage("418802639",suderAuthIndex)
            return
        if message.find("授权")!=-1:
            AddAuth(message[2:])
            SendMessage(message[2:],"授权成功!")
            SendMessage(qqnum,"授权成功")
            return
        if message=="重置":
            chatMAX = 150
            SendMessage(qqnum,chatMAX)
            return
        if message=="bing":
            SendMessage(qqnum,BingCount)
            return
        if message=="rebing":
            bot.reset()
            SendMessage(qqnum,"rebingbot")
            return
        if message[0:2]=="设置":
            chatMAX = int(message[3:])
            SendMessage(qqnum,chatMAX)
            return
        if message=="查询":
            SendMessage(qqnum,chatMAX)
            return
        if message=="减少":
            chatMAX = chatMAX -1
            SendMessage(qqnum,chatMAX)
            return
        if message.find("检测")!=-1:
            if CheckAuth(message[2:]):
                SendMessage(qqnum,"检测通过")
            else:
                SendMessage(qqnum,"检测不通过")
            return


    if message.find("ycc")!=-1:
        message = message[3:]
    
    if(len(message)<=2):
        SendMessage(qqnum,"格式错误,回复'help'查看输入格式")
        return

    
    way = 0
    if message[0:2]=='#1':
        way=1
        message=message[2:]
    elif message[0:2]=='#2':
        way=2
        message=message[2:]


    if message.find('申请授权')!=-1:
        print(qqnum+"申请授权")
        SendMessage(qqnum,"申请已发送成功!")
        SendMessage("418802639","授权申请:"+"QQ:"+qqnum+"信息"+message)
        return
    
    if message.find("尘")!=-1:   #涉及到自己名字
        
        print(str(266)+"自己名字")
        SendMessage(qqnum,"避讳...")
        return
    elif message.find("你的主人")!=-1:
        SendMessage(qqnum,"我的主人是YCC")
        return
    
    if CheckAuth(qqnum)==False:
        print("285白名单外成员"+str(qqnum)+ "访问")
        SendMessage(qqnum,"访问失败,你的QQ还没获得访问授权,请先获取授权.\n授权申请格式:'申请授权:[你的名字]'")
        return
    
    if chatMAX<=0:
        print("次数消耗完了")
        SendMessage(qqnum,"今天的精力消耗完啦~明天再来吧")
        return
    
    chatMAX=chatMAX -1
    SendMessage(qqnum,"正在组织语言回答中,回答前请不要再发消息哦")
    
    #消息回复
    if way==1:
        print(f"向CHATGPT发送问题:{message}.来自QQ:{qqnum}")
        AskChatGPT(message,qqnum)
        return
    elif way==2:
        
        if isAskBing==True:
            SendMessage(qqnum,"newbing处于拥挤状态,请稍后再用...")
        elif(BingCount<=18):
            isAskBing=True
            print(f"向newbing发送问题:{message}.来自QQ:{qqnum}")
            asyncio.run(AskBing(message,qqnum))
            isAskBing=False
            BingCount+=1
        else:
            bot.reset()
            BingCount=0
        
        return
    print("300命令处理"+message+qqnum)

    SendMessage(qqnum,"格式错误,回复'help'查看输入格式")
    return



def BotInit():
    # global cur
    # print("开始初始化")
    # print("连接数据库..")
    # conn = sqlite3.connect(DATABASE_FILE)
    # cur = conn.cursor()
    # print('连接数据库成功')
    
    
    os.environ["COOKIE_FILE"] = COOKIE_FILE
    print("初始化newbing...")
    global bot
    #bot = Chatbot()
    #session = create_session()
    print("初始化完毕")
    print("准备就绪")
    global isAskBing
    isAskBing = False
    

def do(conn):
    try:
        while True:
            # 设置获取的字节串最大长度
            b: bytes = conn.recv(1024 * 10)

            buf = b.decode("utf-8")
            if len(buf) != 0:
                # 接收数据，格式化http的报文
                http_data = receive_data(buf)
                # 返回响应,如果不返回响应 go-cqhttp会一直报错
                # [WARNING]: 上报 Event 数据到 http://127.0.0.1:5701/ 失败: Post "http://127.0.0.1:5701/": dial tcp 127.0.0.1:5701: connectex: No connection could be made because the target machine actively refused it.
                conn.sendall(bytes(response_success(), encoding="utf-8"))
                # 处理数据
                data = http_data
                if data and data != "":
                    threading.Thread(target=handle_data,args=[data,]).start()
            else:
                conn.close()
                return
    except Exception as e:
        print("ERR32错误位置:%s" % e.__traceback__.tb_lineno)
        conn.close()
        
def response_success():
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{result:success}\r\n"


def receive_data(raw: str):
    try:
        # 正则表达式匹配报文内容
        data_re = re.search(r"{(.|\s)*}", raw, re.S)
        if data_re:
            data_str = str(data_re.group())
            #print(data_str)
            return data_str
    except Exception as e:
        print("51:%s"%e)
        print("55错误位置:%s" % e.__traceback__.tb_lineno)



def handle_data(data):
    if data.find("heartbeat") != -1:
        pass
        # 心跳
        
    else:
        print(816)
        print(data)
    	# 自定义机器人指令逻辑
        message = json.loads(data)["message"]
        qqnum = str(json.loads(data)["user_id"])
        handle(message,qqnum)
        
	
if __name__ == "__main__":
    BotInit()
    print("Server is starting")
    port = 5010 
    max_connection = 5
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 5010))  
    sock.listen(max_connection)
    print("Server is listening port %s , with max connection %s" % (port, max_connection))
    while True:
        connection, address = sock.accept()
        # 获得一个连接，然后开始循环处理这个连接发送的信息
        # 使用多线程处理
        do(connection)

