import os
import subprocess
import re
import requests
import sys
from PyQt5.QtCore import pyqtSignal, QObject
from logger import get_logger, log_ip_extraction, log_error

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 移除不正确的导入，这个文件只负责提取IP，不负责分析
def list_established_ips(progress_updater=None):
    try:
        get_logger().info("开始提取系统网络连接中的外部IP地址")
        
        # 运行netstat命令
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            log_error("执行netstat命令失败", "IP提取")
            return

        # 提取状态为ESTABLISHED的行
        established_lines = [line for line in result.stdout.splitlines() if 'ESTABLISHED' in line]
        get_logger().debug(f"找到 {len(established_lines)} 个ESTABLISHED连接")

        # 从netstat输出中筛选状态为ESTABLISHED的行
        # 提取外部IP地址（外部连接）
        # 去除重复的IP地址并保存到文件
        ip_addresses = []
        total_lines = len(established_lines)
        for index, line in enumerate(established_lines):
            columns = line.split()
            if len(columns) >= 3:
                foreign_address = columns[2]  # 外部地址通常是第三列
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', foreign_address)
                if ip_match:
                    ip_addresses.append(ip_match.group(1))

            # 更新进度
            if progress_updater:
                progress = int((index + 1) / total_lines * 100)
                progress_updater.progress_signal.emit(progress)

        # 从IP地址列表中去除重复项
        unique_ips = set(ip_addresses)
        get_logger().debug(f"提取到 {len(ip_addresses)} 个IP地址，去重后得到 {len(unique_ips)} 个唯一IP")

        # 将唯一的外部IP保存到文件（保存在IPFind文件夹下）
        ip_file_path = os.path.join(os.path.dirname(__file__), 'ips.txt')
        with open(ip_file_path, 'w') as f:
            for ip in unique_ips:
                f.write(ip + '\n')

        log_ip_extraction(len(unique_ips), ip_file_path)

    except Exception as e:
        log_error(f"发生错误: {e}", "IP提取")
        print(f"发生错误: {e}")
