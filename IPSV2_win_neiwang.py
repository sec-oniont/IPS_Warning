#!coding:utf-8
from socket import *
import pygame,re

tmpSip = ''
tmpDip = ''
tmpEventName = ''
URL1 = '/user/loginid/?id=3'
URL2 = '/user/loginid/?id=-'
URL3 = '/login.action?' #红队struts2特征
URLxss = ''

#!红队IP
#Sip = ['1.50.73.179','210.72.243.18','114.212.71.226','114.212.71.227','114.212.71.228','114.212.71.229','114.212.71.230','114.212.71.231','114.212.71.232','114.212.71.233','114.212.71.234','114.212.71.235','114.212.71.236','114.212.71.237','114.212.71.238','114.212.71.239','114.212.71.240','114.212.71.241','114.212.71.242','114.212.71.243','114.212.71.244','114.212.71.245','114.212.71.246','114.212.71.247','114.212.71.248','114.212.71.249','114.212.71.250','114.212.71.251','114.212.71.252','114.212.71.253','114.212.71.254','10.68.24.145','10.68.23.3','10.68.23.8','10.68.23.10','10.68.23.35','10.68.23.66','10.68.23.95','10.68.23.97','10.68.23.225','114.115.170.98','106.13.113.74','139.9.47.143','124.160.31.138','101.69.65.170','60.12.13.74','122.224.205.179','47.110.49.237','119.3.221.200','222.222.39.180','101.68.65.170','122.224.200.179','114.115.170.95','106.10.113.74','172.16.26.3','172.16.26.124']
#省内IP地址
Self_IP1 = '10.216.'
Self_IP2 = '10.217.'

#接收IPS告警
revlog = socket(AF_INET,SOCK_DGRAM)
addr = ('172.16.26.124',514)
revlog.bind(addr)
while True:
    receive_data = revlog.recvfrom(204800)
    date = receive_data[0]#decode('gbk')存储接收的数据
    addr = receive_data[1]
    Dev_ip = addr[0]
    port = addr[1]
    
    try:
        #监测红队IP
        SrcIP = str(re.findall("SrcIP=+(\d+\S+)",date)[0])
        DstIP = str(re.findall("DstIP=+(\d+\S+)",date)[0])
        EventName = str(re.findall("EventName=+(\S+)",date)[0])
        SecurityType = str(re.findall("SecurityType=+(\S+)",date)[0])
        ProtocolType = str(re.findall("ProtocolType=+(\S+)",date)[0])
        Action = str(re.findall("Action=+(\w+)",date)[0])
    except:
        continue

    print "=",#日志接收状态

    #判断地址是否省外
    if Self_IP1 in SrcIP or Self_IP2 in SrcIP:continue


    #告警
    pygame.mixer.init()
    track = pygame.mixer.music.load(r"E:\auto-tools\gaojing.mp3")
    pygame.mixer.music.play()
    print u"针对IP的监测"*3 #调试
    print "+++++ This is IPS +++++\n"
    print "检测到红队攻击IP %s 目标服务器IP：%s 安全事件：%s 类型：%s 动作：%s".decode('UTF-8').encode('GBK') %(SrcIP,DstIP,EventName,SecurityType,Action)
    print "+++"*10

    #写入文件
    with open("Resul_Summary.txt", 'a+') as log:
        log.write("检测到红队攻击IP:  ".decode('utf-8').encode('gb2312') + SrcIP + "  " + "目标服务器IP:  ".decode('utf-8').encode('gb2312') + DstIP + "  "  + "安全事件等级: ".decode('utf-8').encode('gb2312') + EventName + "  "  + "类型: ".decode('utf-8').encode('gb2312') + SecurityType + "  "  + "动作: ".decode('utf-8').encode('gb2312') + Action + '\n')
    