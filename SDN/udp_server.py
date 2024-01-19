from scapy.all import *
import binascii
import redis
import time

redis_server_ip = '172.25.7.137'
src_ip = '192.168.95.27'
src_port = 19045
dst_ip = '192.168.111.137'
dst_port = 22631
interface = 'enp23s0f1'
filter = 'src host ' + src_ip + ' and src port ' + str(src_port) + ' and dst host ' + dst_ip + ' and dst port ' + str(dst_port)

while True:
    time1 = time.time()
    
    # Scapy抓包
    packet = ''
    data = ''
    packet = sniff(count = 1, iface = interface, filter = filter)
    # packet.summary()
    # wrpcap("/root/shit.pcap", packet)
    data = packet[0].load

    # 解码并转换, 如果解码后是字典, 将数据存入Redis服务器中
    data = binascii.a2b_hex(data)
    data = data.decode()
    data = eval(data)
    if not isinstance(data, dict):
        continue
    pool = redis.ConnectionPool(host = redis_server_ip, port = 6379, db = 0)
    r = redis.StrictRedis(connection_pool = pool)
    for key in data.keys():
        value = str(data[key])
        r.set(key, value)
        print('%s: %s'%(key, r.get(key).decode()))
    print("---------------")
    
    time2 = time.time()
    print('Took: '+str(time2 - time1)+' s')
    
    #time.sleep(3)
