#coding=UTF-8
import sys
import time
import re
import psutil
import json
import subprocess
import socket
from scapy.all import *

# 获取CPU空闲资源 (%)
def get_cpu(ssh_host = None):
    cpu_idel = 0.0
    if ssh_host is not None:
        cmd = []
        cmd.append('ssh')
        cmd.append(ssh_host)
        cmd.append('python')
        cmd.append('-c')
        cmd.append('\"import psutil; print(min(psutil.cpu_percent(interval = 1), 100))\"')
        cpu_idle = 100.0 - float(subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0])
    else:
        cpu_idle = min(psutil.cpu_percent(interval = 1), 100)
    return cpu_idle

# 获取内存空闲资源 (MiB)
def get_mem(ssh_host = None):
    mem_idle = 0.0
    if ssh_host is not None:
        cmd = []
        cmd.append('ssh')
        cmd.append(ssh_host)
        cmd.append('python')
        cmd.append('-c')
        cmd.append('\"import psutil; print(psutil.virtual_memory().free/1024/1024)\"')
        mem_idle = float(subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0])
    else:
        mem_idle = psutil.virtual_memory().free/1024/1024
    return mem_idle

# 获取OSD读写速度 (KiB/s)
def get_osd_io(ssh_host = None):
    # 从 'ceph-volume lvm list' 命令获取OSD的ID与对应的磁盘PV
    cmd = []
    if ssh_host is not None:
        cmd.append('ssh')
        cmd.append(ssh_host)
    cmd.append('ceph-volume')
    cmd.append('lvm')
    cmd.append('list')
    cmd.append('--format=json')
    osd_disk_original = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0]
    osd_disk_original = json.loads(osd_disk_original)
    osd_disk_original = json.dumps(osd_disk_original)
    osd_disk_original = eval(osd_disk_original)
    osd_disk = {}
    for osd_id in osd_disk_original.keys():
        osd_disk[osd_id] = osd_disk_original[osd_id][0]['devices'][0][5:]
    # 匹配OSD的ID及其读写速度, 例如: osd_io --> result:{0: 0.0, 39: 0.0, 10: 0.0, 49: 0.0, 23: 0.0, 59: 0.0}
    osd_io = {}
    for osd_id in osd_disk.keys():
        if ssh_host is not None:
            cmd = []
            cmd.append('ssh')
            cmd.append(ssh_host)
            cmd.append('python')
            cmd.append('-c')
            cmd.append('"import psutil; import time; pre_read_bytes = psutil.disk_io_counters(perdisk = True)[\'' + osd_disk[osd_id] + '\'].read_bytes; pre_write_bytes = psutil.disk_io_counters(perdisk = True)[\'' + osd_disk[osd_id] + '\'].write_bytes; time.sleep(1); after_read_bytes = psutil.disk_io_counters(perdisk = True)[\'' + osd_disk[osd_id] + '\'].read_bytes; after_write_bytes = psutil.disk_io_counters(perdisk = True)[\'' + osd_disk[osd_id] + '\'].write_bytes; print(after_read_bytes - pre_read_bytes + after_write_bytes - pre_write_bytes)"')
            io = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0]
            osd_io[osd_id] = float(io.decode())/1024
        else:
            pre_read_bytes = psutil.disk_io_counters(perdisk = True)[osd_disk[osd_id]].read_bytes
            pre_write_bytes = psutil.disk_io_counters(perdisk = True)[osd_disk[osd_id]].write_bytes
            time.sleep(1)
            after_read_bytes = psutil.disk_io_counters(perdisk = True)[osd_disk[osd_id]].read_bytes
            after_write_bytes = psutil.disk_io_counters(perdisk = True)[osd_disk[osd_id]].write_bytes
            osd_io[osd_id] = float(after_read_bytes - pre_read_bytes + after_write_bytes - pre_write_bytes)/1024
    return osd_io

# 获取OSD等级
def get_osd_class(ssh_host):
    #从 'ceph osd tree' 命令获取OSD的ID与对应的磁盘PV
    cmd = []
    if ssh_host is not None:
        cmd.append('ssh')
        cmd.append(ssh_host)
    cmd.append('ceph')
    cmd.append('osd')
    cmd.append('tree')
    #osd_class_result = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0]
    #osd_class_lines = osd_class_result.decode().split('\n')
    #osd_class = {}
    #pattern = re.compile(r'(.*)osd(.*)')
    #for line in osd_class_lines:
    #    if pattern.match(line) is not None:
    #        split = line.split(' ')
    #        split_notNone = []
    #        for i in split:
    #            if (i != None) and (i != ''):
    #                split_notNone.append(i)
    #        osd_id = split_notNone[0]
    #        _class = split_notNone[1]
    #        osd_class[osd_id] = _class
    cmd.append('--format=json')
    osd_class_original = subprocess.Popen(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT).communicate()[0]
    osd_class_original = json.loads(osd_class_original)
    osd_class_original = json.dumps(osd_class_original)
    osd_class_original = eval(osd_class_original)
    osd_class = {}
    for node in osd_class_original['nodes']:
        id = node['id']
        if id >= 0:
            osd_class[str(id)] = node['device_class']
    return osd_class

# UDP报文发送: 指定一个当前交换机路由表找不到的地址, 触发匹配流表table-miss, 并将信息上传给SDN控制器
def send_data(ssh_host, scapy_src_host_ip, class_all):
    while True:
        try:
            time1 = time.time()
            cpu = get_cpu(ssh_host)
            mem = get_mem(ssh_host)
            io = get_osd_io(ssh_host)
            _class = {}
            for key in io.keys():
                _class[key] = class_all[key]
            data = str((_class, cpu, mem, io))
            print(data)
            send(IP(src = scapy_src_host_ip, dst = '192.168.111.253')/UDP(dport = 12345)/Raw(load = data)) # dst为SDN网段内不可访问的IP地址
            time2 = time.time()
            print('Took: '+str(time2 - time1)+' s')
            #time.sleep(1)
        except Exception as e:
            raise e;

if __name__ == '__main__':
    #print(sys.argv)
    ssh_host = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('192.168.111.137', 80)) # 指定SDN网段内可访问的IP地址
    scapy_src_host_ip = s.getsockname()[0] # 获取本机在SDN网段内的IP地址作为scapy发包的源IP地址
    if len(sys.argv) >= 2:
        ssh_host = sys.argv[1]
    if len(sys.argv) >= 3:
        scapy_src_host_ip = sys.argv[2]
    class_all = get_osd_class(ssh_host)
    send_data(ssh_host, scapy_src_host_ip, class_all)
