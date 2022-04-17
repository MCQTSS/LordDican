# LordDican Server
# CodeBy MCQTSS
import json
import re
import os
import base64
import hashlib
import configparser
import threading
import urllib.request
import urllib.error
import traceback
import time
import gevent
from gevent import socket, monkey

monkey.patch_all()


class Network_verification:
    def __init__(self):
        MCQTSS_F.MCQTSS_print_Compulsory("MCQTSS.Network.verification已加载完成inti", 'Inti')

    def register(self, username, password, qq, hwid, Player_ID):
        config = configparser.ConfigParser()
        config.read("userinfo.ini")
        register_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        if len(username) <= 5:
            return 202
            # 用户名长度过短
        elif len(password) <= 5:
            return 203
            # 密码长度过短
        if len(username) >= 10:
            return 204
            # 用户名长度过长
        elif len(password) >= 20:
            return 205
            # 密码长度过长
        try:
            qq_ = int(qq)  # 检查转换到int是否存在其他字符串
            if len(qq) <= 5:
                return 206
                # QQ输入有误
        except:
            return 206
        try:
            config.add_section(username)
        except configparser.DuplicateSectionError:
            return 201
            # 账户已存在
        except:
            return 503
        config.set(username, "username", username)
        config.set(username, "password", password)
        config.set(username, "qq", qq)
        config.set(username, "hwid", hwid)
        config.set(username, "mode", '0')
        config.set(username, "register_time", register_time)
        config.set(username, "MinecraftServer_Player_ID", Player_ID)
        config.set(username, "MinecraftServer_Username", '')
        config.set(username, "MinecraftServer_Password", '')
        with open("userinfo.ini", 'w+') as fh:
            config.write(fh)
        MCQTSS_F.MCQTSS_print_Compulsory("用户名:{} 注册成功".format(username), 'Register')
        return 200

    def get_register_return(self, code):
        if code == 200:
            text = "注册成功"
        elif code == 201:
            text = "账户已存在"
        elif code == 202:
            text = "用户名长度过短"
        elif code == 203:
            text = "密码长度过短"
        elif code == 204:
            text = "用户名长度过长"
        elif code == 205:
            text = "密码长度过长"
        elif code == 206:
            text = "QQ输入有误"
        elif code == 503:
            text = "服务器错误"
        else:
            text = "ServerError:无法判断的返回码"
        return_info = {
            "code": code,
            "message": text
        }
        return json.dumps(return_info)

    def login(self, username, password, hwid):
        config = configparser.ConfigParser()
        config.read("userinfo.ini")
        try:
            if config.get(username, "mode") == '2' or hwid in hwid_ban_list:
                return 205
                # Hwid被封禁
            if int(config.get(username, "qq")) in qq_ban_list or len(config.get(username, "qq")) <= 5:
                return 203
                # QQ被封禁
            if config.get(username, "password") != password:
                return 202
                # 密码错误
            if config.get(username, "hwid") != hwid:
                try:
                    old_hwid = json.loads(config.get(username, "old_hwid"))
                except:
                    old_hwid = {'data': []}
                    pass
                old_hwid['data'].append(
                    {'Hwid': config.get(username, 'hwid'),
                     'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))})
                config.set(username, 'old_hwid', json.dumps(old_hwid))
                config.set(username, 'hwid', hwid)
                # return 200
                # Hwid错误
        except configparser.NoSectionError:
            return 201
            # 账户不存在
        except configparser.NoOptionError:
            return 501
            # 用户数据异常
        except:
            return 502
        try:
            config.set(username, "LastLoginTime", time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
            with open("userinfo.ini", 'w+') as fh:
                config.write(fh)
            MCQTSS_F.MCQTSS_print_Compulsory("用户名:{} 登录成功".format(username), 'Login')
            return 200
        except:
            return 504

    def get_login_return(self, code, username):
        config = configparser.ConfigParser()
        config.read("userinfo.ini")
        if code == 200:
            text = "登录成功"
        elif code == 201:
            text = "用户不存在"
        elif code == 202:
            text = "密码错误"
        elif code == 203:
            text = "QQ被封禁或注册时输入有误"
        elif code == 204:
            text = "账户被封禁"
        elif code == 205:
            text = "机器码被封禁"
        elif code == 501 or code == 502:
            text = "用户数据异常"
        elif code == 504:
            text = "写入登录数据异常"
        else:
            text = "ServerError:无法判断的返回码"
        return_info = {
            "code": code,
            "message": text,
            'Player_ID': config.get(username, 'MinecraftServer_Player_ID')
        }
        return json.dumps(return_info)

    def get_login_ban_info(self, username):
        config = configparser.ConfigParser()
        config.read("userinfo.ini")
        try:
            if config.get(username, "mode") == '0':
                return json.dumps({'code': 201, 'message': '账户未封禁'})
            else:
                return json.dumps({'code': 200, 'message': '封禁原因:{}'.format(config.get(username, "ban_info"))})
        except:
            return json.dumps({'code': 500, 'message': '服务器异常'})

    def update(self, username, password, hwid, versio, info):
        if self.login(username, password, hwid) != 200:
            return 203
        config = configparser.ConfigParser()
        config.read('versio.ini')
        try:
            if config.get(versio, 'state') != 'True':
                MCQTSS_F.MCQTSS_print_Compulsory("用户名:{} 版本号:{} 需要更新(State)".format(username, versio), 'Update')
                return 201
            if config.get(versio, 'update_info') is not info:
                MCQTSS_F.MCQTSS_print_Compulsory("用户名:{} 版本号:{} 需要更新(Info)".format(username, versio), 'Update')
                return 202
            MCQTSS_F.MCQTSS_print_Compulsory("用户名:{} 版本号:{} 无需更新".format(username, versio), 'Update')
            return 200
        except configparser.NoSectionError:
            return 201
        except configparser.NoOptionError:
            return 501
        except:
            return 502

    def get_update_return(self, code):
        if code == 200:
            msg = '无需更新'
        elif code == 501 or code == 502:
            msg = '服务端异常'
        elif code == 202:
            msg = '客户端程序异常'
        elif code == 201:
            msg = '需要更新,已回发最新版本信息'
        elif code == 203:
            msg = '登录信息验证失败'
        else:
            msg = "ServerError:无法判断的返回码"
        return_info = {
            "code": code,
            "message": msg
        }
        return json.dumps(return_info)

    def get_update_info(self, username, password, hwid):
        if self.login(username, password, hwid) != 200:
            return json.dumps({
                "code": 201,
                "message": '账号信息验证失败'
            })
        config = configparser.ConfigParser()
        config.read('versio.ini')
        try:
            versio = config.get('main', 'new')
            MCQTSS_F.MCQTSS_print_Compulsory(
                "用户名:{} 版本号:{} 更新信息已发送 信息:{}".format(username, versio, config.get(versio, 'update_info')),
                'GetUpdateInfo')
            return json.dumps({
                "code": 200,
                "message": '获取成功',
                'info': config.get(versio, 'update_info')
            })
        except configparser.NoOptionError:
            return json.dumps({
                "code": 501,
                "message": '服务端异常'
            })
        except:
            traceback.print_exc()
            return json.dumps({
                "code": 502,
                "message": '服务端异常'
            })


class QQ_Music:
    def __init__(self):
        pass
        # 没开始写,搜索和音乐获取由于涉嫌Cookie会丢到MCQTSS服务器解析


class MCQTSS_encryption:
    def __init__(self):
        MCQTSS_F.MCQTSS_print_Compulsory("MCQTSS.encryption已加载完成inti", 'Inti')

    def MCQTSS_md5(self, text):
        md5 = hashlib.md5()
        md5.update(bytes(text, encoding=Server_decode))
        return md5.hexdigest()

    def MCQTSS_sha256(self, text):
        sha256 = hashlib.sha256()
        sha256.update(bytes(text, encoding=Server_decode))
        return sha256.hexdigest()

    def MCQTSS_str_base64(self, text):
        try:
            return base64.b64encode(text.encode())
        except:
            return "Error"

    def MCQTSS_base64_str(self, text):
        try:
            return base64.b64decode(text).decode(Server_decode)
        except:
            return "Error"


class MCQTSS_Function:
    def __init__(self):
        self.MCQTSS_mkdir()
        self.MCQTSS_print_Compulsory("MCQTSS.Function已加载完成inti", 'Inti')

    def MCQTSS_mkdir(self):
        dir_list = ['data', 'log']
        for i in range(len(dir_list)):
            try:
                os.mkdir(dir_list[i])
            except FileExistsError:
                pass

    def MCQTSS_Read_Text(self, file_name):
        try:
            with open(file_name, encoding=Server_decode) as file_obj:
                return file_obj.read()
        except:
            return "Error"

    def MCQTSS_HTTP_read_text(self, url):
        html = urllib.request.urlopen(url).read()
        return html

    def MCQTSS_qzjwb(self, text, start_str, end):
        start = text.find(start_str)
        if start >= 0:
            start += len(start_str)
            end = text.find(end, start)
            if end >= 0:
                return text[start:end].strip()

    def MCQTSS_Print(self, text, mode='Conventional'):
        if Server_output:
            print("[Debug_{}][{}] {}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), mode, text))

    def MCQTSS_print_Compulsory(self, text, mode='Conventional'):
        print("[{}][{}] {}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), mode, text))

    def MCQTSS_Error_Print(self, text1, text2):
        try:
            print("[{}][Error] 位于{} 发生异常 原因:{}".format(
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                text1,
                text2))
        except:
            pass

    def MCQTSS_Write_Log_Server(self, adder, data, ret_msg):
        datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        logtime = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        self.MCQTSS_Write(
            "[" + datatime + "]\nAdder:{}\n数据:{}\n返回的数据:{}\n\n".format(adder, data, ret_msg),
            r"./log/{}.txt".format(logtime), 'a+')

    def MCQTSS_Write(self, content, path, mode='a+'):
        fh = open(path, mode)
        fh.write(content)
        fh.close()

    def MCQTSS_Format_detection_Mail(self, mail):
        if re.match("^.+@(\\[?)[a-zA-Z0-9\\-.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", mail) is not None:
            return True
        else:
            return False

    def MCQTSS_Send_Socket(self, ip, port, data):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((ip, port))
        tcp_socket.send(data)
        data = tcp_socket.recv(10240).decode(Server_decode)
        tcp_socket.close()
        return data


class MCQTSS_Server_Main:
    def __init__(self):
        MCQTSS_F.MCQTSS_print_Compulsory("MCQTSS.Server.Main已加载完成inti", 'Inti')

    def MCQTSS_Run_Server(self, port):
        MCQTSS_F.MCQTSS_print_Compulsory('ServerPort:{} 服务端线程创建完成'.format(port))
        PySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        PySocket.bind(('0.0.0.0', port))
        PySocket.listen(500)
        while True:
            cli, adder = PySocket.accept()  # socket sever到这步默认会生成一个线程，把请求交给线程处理
            MCQTSS_F.MCQTSS_Print('客户连接:{}'.format(adder), 'User_Connection')
            # 但这里是交给协程处理（cli就是客户端连过来而在服务器端为其生成的一个连接实例）
            gevent.spawn(self.handle_request, cli, adder)  # 启动一个协程
            # 把客户端请求连接生成的实例cli交给handle_request方法

    def handle_request(self, conn, adder):  # 负责处理和客户端请求的所有交互
        global Connect_Close
        try:
            Connect_Close = False
            while True:
                Data = conn.recv(10240).decode('gbk')
                if len(Data) <= 10:
                    conn.sendto(
                        bytes(json.dumps({'code': 401.4, 'message': '错误请求:未发送数据'}), Server_decode),
                        adder)
                    if not Connect_Close:
                        Connect_Close = True
                        conn.shutdown(socket.SHUT_WR)
                        return 0
                    MCQTSS_F.MCQTSS_Error_Print('MCQTSS.ServerMain', '包长度过短')
                elif not Data:
                    conn.sendto(
                        bytes(json.dumps({'code': 401.4, 'message': '错误请求:未发送数据'}), Server_decode),
                        adder)
                    if not Connect_Close:
                        Connect_Close = True
                        conn.shutdown(socket.SHUT_WR)
                        return 0
                    MCQTSS_F.MCQTSS_Error_Print('MCQTSS.ServerMain', '未发送数据')
                MCQTSS_F.MCQTSS_Print(Data, 'Adder:{} Data'.format(adder))
                if Data == 'MCQTSS_Create a connection':
                    conn.sendto(bytes(json.dumps({'code': 100, 'message': 'Server_Receive'}), Server_decode), adder)
                elif Data == 'Connect_Close':
                    conn.sendto(bytes(json.dumps({'code': 200, 'message': 'success'}), Server_decode), adder)
                    if not Connect_Close:
                        Connect_Close = True
                        conn.close()
                        return 0
                    MCQTSS_F.MCQTSS_Print('断开客户(主动):{}'.format(adder), 'Disconnect_User')
                else:
                    try:
                        ret_json = json.loads(Data)
                    except UnicodeError or json.decoder.JSONDecodeError or json.decoder.JSONDecoder:
                        conn.sendto(bytes(json.dumps(
                            {'code': 400, 'message': '错误请求:请求数据错误,服务器无法解析'}),
                            Server_decode), adder)
                        return 0
                    except:
                        conn.sendto(bytes(json.dumps(
                            {'code': 400.1, 'message': '错误请求:请求数据错误,服务器无法解析'}),
                            Server_decode), adder)
                        return 0
                    try:
                        Request_mode = ret_json['mode']
                    except KeyError:
                        Request_mode = 'Error'
                        conn.sendto(
                            bytes(json.dumps({'code': 401.1, 'message': '错误请求:提交数据不合法'}), Server_decode),
                            adder)
                        if not Connect_Close:
                            Connect_Close = True
                            conn.close()
                            return 0
                    if Request_mode == 'register':
                        ret_msg = MCQTSS_NV.get_register_return(
                            MCQTSS_NV.register(ret_json['username'], ret_json['password'], ret_json['QQ'],
                                               ret_json['hwid'], ret_json['Player_ID']))
                    elif Request_mode == 'login':
                        ret_msg = MCQTSS_NV.get_login_return(
                            MCQTSS_NV.login(ret_json['username'], ret_json['password'], ret_json['hwid']),
                            ret_json['username'])
                    elif Request_mode == 'update':
                        ret_msg = MCQTSS_NV.get_update_return(
                            MCQTSS_NV.update(ret_json['username'], ret_json['password'], ret_json['hwid'],
                                             ret_json['versio'], ret_json['info']))
                    elif Request_mode == 'get_update_info':
                        ret_msg = MCQTSS_NV.get_update_info(ret_json['username'], ret_json['password'],
                                                            ret_json['hwid'])
                    elif Request_mode == 'get_ban_info':
                        ret_msg = MCQTSS_NV.get_login_ban_info(ret_json['username'])
                    else:
                        ret_msg = json.dumps(
                            {"code": 404, "message": "The data is not submitted or the data is illegal"})
                    MCQTSS_F.MCQTSS_Write_Log_Server(str(adder), Data, ret_json)
                    try:
                        conn.sendto(bytes(ret_msg, Server_decode), adder)
                    except:
                        if not Connect_Close:
                            Connect_Close = True
                            conn.close()
                            MCQTSS_F.MCQTSS_Print('断开客户:{}'.format(adder), 'Disconnect_User')
                            return 0

        except Exception as ex:
            conn.sendto(bytes(json.dumps(
                {'code': 500, 'message': '服务器内部发生异常:{}'.format(ex)}),
                Server_decode), adder)
            MCQTSS_F.MCQTSS_Error_Print('MCQTSS.ServerMain', ex)
            traceback.print_exc()
            if not Connect_Close:
                Connect_Close = True
                conn.close()
                return 0
        finally:
            if not Connect_Close:
                Connect_Close = True
                conn.close()
                return 0
            MCQTSS_F.MCQTSS_Print('断开客户:{}'.format(adder), 'Disconnect_User')


if __name__ == '__main__':
    Server_decode = 'gbk'
    hwid_ban_list = []
    qq_ban_list = []
    Run_Path = str(os.path.dirname((os.path.abspath(__file__)))).replace('\\', "/")
    Server_output = False
    MCQTSS_F = MCQTSS_Function()
    MCQTSS_F.MCQTSS_print_Compulsory('Debug模式:{}'.format(Server_output))
    MCQTSS_E = MCQTSS_encryption()
    MCQTSS_NV = Network_verification()
    MCQTSS_M = MCQTSS_Server_Main()
    threading.Thread(target=MCQTSS_M.MCQTSS_Run_Server, kwargs={'port': 5100}).start()
