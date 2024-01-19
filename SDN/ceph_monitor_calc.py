import redis
import copy
import math
import time

def get_osd_info(r):
    host_info = {}
    for i in range(137, 140):
        key = '192.168.111.' + str(i)
        host_info[key] = eval(r.get(key).decode())

    osd_info = {}
    for host in host_info.keys():
        for osd in host_info[host]['class'].keys():
            info = {}
            for info_type in host_info[host].keys():
                if info_type == 'class':
                    if host_info[host][info_type][osd] == 'ssd':
                        info[info_type] = 10
                    else:
                        info[info_type] = 1
                elif info_type == 'io':
                    info[info_type] = host_info[host][info_type][osd] * -1
                else:
                    info[info_type] = host_info[host][info_type]
            osd_info[osd] = info
    return osd_info

def calc_osd_performance(osd_info):
    osd_list = list(osd_info.keys())

    osd_info_sum = {}
    for info_type in osd_info[osd_list[0]].keys():
        osd_info_sum[info_type] = 0.0
    for osd in osd_list:
        for info_type in osd_info[osd].keys():
            osd_info_sum[info_type] += osd_info[osd][info_type] ** 2

    osd_info_normal = copy.deepcopy(osd_info)
    for osd in osd_list:
        for info_type in osd_info_normal[osd].keys():
            osd_info_normal[osd][info_type] = osd_info_normal[osd][info_type] / math.sqrt(osd_info_sum[info_type])

    weight = {'bw': 22, 'class': 52, 'cpu': 2, 'mem': 2, 'io': 22}
    
    osd_info_weight = copy.deepcopy(osd_info_normal)
    for osd in osd_list:
        for info_type in osd_info_weight[osd].keys():
            osd_info_weight[osd][info_type] *= weight[info_type]

    osd_info_max = copy.deepcopy(osd_info_weight[osd_list[0]])
    for osd in osd_list:
        for info_type in osd_info_weight[osd].keys():
            if osd_info_max[info_type] < osd_info_weight[osd][info_type]:
                osd_info_max[info_type] = osd_info_weight[osd][info_type]

    osd_info_min = copy.deepcopy(osd_info_weight[osd_list[0]])
    for osd in osd_list:
        for info_type in osd_info_weight[osd].keys():
            if osd_info_min[info_type] > osd_info_weight[osd][info_type]:
                osd_info_min[info_type] = osd_info_weight[osd][info_type]

    distance_plus = {}
    for osd in osd_list:
        distance_plus[osd] = 0.0
    for osd in osd_list:
        for info_type in osd_info_weight[osd].keys():
            distance_plus[osd] += (osd_info_weight[osd][info_type] - osd_info_max[info_type]) ** 2
        distance_plus[osd] = math.sqrt(distance_plus[osd])

    distance_negative = {}
    for osd in osd_list:
        distance_negative[osd] = 0.0
    for osd in osd_list:
        for info_type in osd_info_weight[osd].keys():
            distance_negative[osd] += (osd_info_weight[osd][info_type] - osd_info_min[info_type]) ** 2
        distance_negative[osd] = math.sqrt(distance_negative[osd])

    closeness = {}
    for osd in osd_list:
        closeness[osd] = distance_negative[osd] / (distance_plus[osd] + distance_negative[osd])

    return closeness

def write_osd_load(osd_performance, scale, r):
    osd_load = {}
    for osd in osd_performance.keys():
        osd_load[osd] = int(scale - osd_performance[osd] * scale)
        key = 'OSD Load Base '+str(osd)
        value = str(osd_load[osd])
        r.set(key, value)
        print('%s: %s'%(key, r.get(key).decode()))

if __name__ == "__main__":
    scale = 100
    redis_server_ip = '172.25.7.137'
    pool = redis.ConnectionPool(host = redis_server_ip, port = 6379, db = 0)
    r = redis.StrictRedis(connection_pool = pool)
    while True:
        time1 = time.time()
        osd_info = get_osd_info(r)
        osd_performance = calc_osd_performance(osd_info)
        write_osd_load(osd_performance, scale, r)
        time2 = time.time()
        print('Took: ' + str(time2 - time1) + 's')
        time.sleep(2)