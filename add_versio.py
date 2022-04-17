import configparser
import json

config = configparser.ConfigParser()
config.read('versio.ini')
versio = input('请输入要添加的版本号:')
state = int(input('激活状态(1开启0或其他不激活):'))
print(
    '下面开始输入需要更新的文件信息 保存位置输入exit(小写)退出输入并保存\nLordDican__Main-主程序更新 LordDican__MServerIP-客户端进服IP(地址写在下载URL里剩下的空) '
    'LordDican__JavaPath-Java下载地址 LordDican__ModsPath-Mods下载地址 '
    'LordDican__MinecraftPath-Minecraft主要文件下载地址 LordDican__MinecraftLibrariesPath-Minecraftlibraries文件夹下载地址 '
    '\n直接输入\\.Minecraft\\mods\\xxx.jar这种为更新客户端目录中的文件')
list_info = []
while True:
    file = input('保存位置:')
    if file == 'exit':
        break
    file_url = input('下载URL:')
    file_md5 = input('文件MD5:')
    file_name = input('文件名:')
    list_info.append({'file': file, 'file_url': file_url, 'file_md5': file_md5, 'file_name': file_name})
update_info = {'versio': versio, 'info': list_info}
try:
    config.add_section('main')
except configparser.DuplicateSectionError:
    pass
if state == 1:
    state = 'True'
    config.set('main', 'new', versio)
else:
    state = 'False'

try:
    config.add_section(str(versio))
except configparser.DuplicateSectionError:
    pass
config.set(versio, 'state', state)
config.set(versio, 'update_info', json.dumps(update_info))
with open("versio.ini", 'w+') as fh:
    config.write(fh)
