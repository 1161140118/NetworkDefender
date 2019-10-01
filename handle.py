# -*- coding: utf-8 -*-

# 以下为特征顺序，每行6个
# index start_time src_addr src_port dst_addr dst_port
# duration src_size dst_size protocol_type land service
# flag wrong_fragment urgent hot num_failed_logins
# logged_in num_compromised root_shell su_attempted num_root num_file_
# creations num_shells num_access_files num_outbound_files is_hot_login is_guest_login


def read_log():
    import os
    if os.path.exists('result.tmp'):
        record = []
        start_time = []  # 网络连接开始时间集
        src_addr = []  # 源地址集
        src_port = []  # 源端口号集
        dst_addr = []  # 目的地址集
        dst_port = []  # 目的端口号集
        network_status = []  # 网络状态集
        with open('result.tmp', 'r') as f:
            for line in f:
                new_record = line.split()
                start_time.append(new_record[1])
                src_addr.append(new_record[2])
                src_port.append(new_record[3])
                dst_addr.append(new_record[4])
                dst_port.append(new_record[5])
                network_status.append(new_record[12])
                record.append(new_record)

        K1 = time_based_features(start_time, dst_addr, dst_port, network_status)
        K2 = host_based_features(src_addr, src_port, dst_addr, dst_port, network_status)

        for i in range(len(record)):
            temp_record = record[i]
            for j in range(9):
                temp_record.append(K1[i][j])
            for j in range(10):
                temp_record.append(K2[i][j])

        return record
    return None  # 没有捕获到包


def time_based_features(start_time, dst_addr, dst_port, network_status, pre_time=2):
    record_num = len(start_time)
    K_ = [[0] * 10] * record_num  # 用于事先统计数量
    for i in range(record_num):
        time_i = float(start_time[i])
        for j in range(i + 1, record_num):
            time_j = float(start_time[j])
            if time_i <= time_j <= time_i + 2:
                if dst_addr[i] == dst_addr[j]:
                    K_[i][0] += 1
                    if network_status[j] in ('S0', 'S1', 'S2', 'S3'):
                        K_[i][2] += 1
                    if network_status[j] == 'REJ':
                        K_[i][4] += 1
                    if dst_port[i] == dst_port[j]:
                        K_[i][6] += 1
                    else:
                        K_[i][7] += 1
                if dst_port[i] == dst_port[j]:
                    K_[i][1] += 1
                    if network_status[j] in ('S0', 'S1', 'S2', 'S3'):
                        K_[i][3] += 1
                    if network_status[j] == 'REJ':
                        K_[i][5] += 1
                    if dst_addr[i] != dst_addr[j]:
                        K_[i][8] += 1
        if K_[i][0] != 0:
            K_[i][2] = K_[i][2] / K_[i][0]
            K_[i][4] = K_[i][4] / K_[i][0]
            K_[i][6] = K_[i][6] / K_[i][0]
            K_[i][7] = K_[i][7] / K_[i][0]
        if K_[i][1] != 0:
            K_[i][3] = K_[i][3] / K_[i][1]
            K_[i][5] = K_[i][5] / K_[i][1]
            K_[i][8] = K_[i][8] / K_[i][1]
    return K_


def host_based_features(src_addr, src_port, dst_addr, dst_port, network_status, pre_back=100):
    record_num = len(src_addr)
    K_ = [[0]*10] * record_num # 用于事先统计数量

    for i in range(record_num):
        j = 0 if i < pre_back else i-pre_back
        for h in range(j, i):
            if dst_addr[h] == dst_addr[i]:
                K_[i][0] += 1
                if src_port[h] == src_port[i]:
                    K_[i][4] += 1
                if network_status[h] in ('S0', 'S1', 'S2', 'S3'):
                    K_[i][6] += 1
                elif network_status[h] == 'REJ':
                    K_[i][8] += 1
                if dst_port[h] == dst_port[i]:
                    K_[i][1] += 1
                    if src_addr[h] != src_addr[i]:
                        K_[i][5] += 1
                        if network_status[h] in ('S0', 'S1', 'S2', 'S3'):
                            K_[i][7] += 1
                        elif network_status[h] == 'REJ':
                            K_[i][9] += 1
                else:
                    K_[i][3] += 1
        if K_[i][0] != 0:
            K_[i][2] = K_[i][1] / K_[i][0]
            K_[i][3] = K_[i][3] / K_[i][0]
            K_[i][4] = K_[i][4] / K_[i][0]
            K_[i][6] = K_[i][6] / K_[i][0]
            K_[i][8] = K_[i][8] / K_[i][0]
        if K_[i][1] != 0:
            K_[i][5] = K_[i][5] / K_[i][1]
            K_[i][7] = K_[i][7] / K_[i][1]
            K_[i][9] = K_[i][9] / K_[i][1]
    return K_


if __name__ == '__main__':
    record = read_log()
    with open('result', 'a') as f:
        for r in record:
            feature_list = [str(feature) for feature in r]
            new_line = ','.join(feature_list)
            f.write(new_line+'\n')
