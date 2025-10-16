import os
import subprocess
import re
import platform
from PyQt5.QtCore import pyqtSignal, QObject
from logger import get_logger, log_ip_extraction, log_error


class IPExtractor:
    """跨平台IP地址提取器"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.logger = get_logger()
    
    def get_network_connections(self):
        """获取网络连接信息，根据系统使用不同的命令"""
        try:
            if self.system == 'windows':
                return self._get_windows_connections()
            elif self.system in ['linux', 'darwin']:  # darwin是macOS
                return self._get_unix_connections()
            else:
                log_error(f"不支持的操作系统: {self.system}", "IP提取")
                return []
        except Exception as e:
            log_error(f"获取网络连接失败: {e}", "IP提取")
            return []
    
    def _get_windows_connections(self):
        """Windows系统使用netstat命令"""
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            raise Exception("执行netstat命令失败")
        return result.stdout.splitlines()
    
    def _get_unix_connections(self):
        """Linux/macOS系统使用ss命令（优先）或netstat命令"""
        # 优先使用ss命令，更现代且性能更好
        try:
            result = subprocess.run(['ss', '-tun'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.splitlines()
        except FileNotFoundError:
            self.logger.debug("ss命令不可用，尝试使用netstat")
        
        # 如果ss不可用，使用netstat
        try:
            result = subprocess.run(['netstat', '-tun'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.splitlines()
            else:
                raise Exception("执行netstat命令失败")
        except FileNotFoundError:
            raise Exception("ss和netstat命令都不可用")
    
    def extract_external_ips(self, progress_updater=None):
        """提取外部IP地址"""
        try:
            self.logger.info(f"开始提取系统网络连接中的外部IP地址 (系统: {self.system})")
            
            # 获取网络连接
            connections = self.get_network_connections()
            if not connections:
                log_error("无法获取网络连接信息", "IP提取")
                return []
            
            # 根据系统类型解析连接
            if self.system == 'windows':
                return self._parse_windows_connections(connections, progress_updater)
            else:
                return self._parse_unix_connections(connections, progress_updater)
                
        except Exception as e:
            log_error(f"提取IP地址失败: {e}", "IP提取")
            return []
    
    def _parse_windows_connections(self, connections, progress_updater):
        """解析Windows系统的网络连接"""
        ip_addresses = []
        established_lines = [line for line in connections if 'ESTABLISHED' in line]
        self.logger.debug(f"找到 {len(established_lines)} 个ESTABLISHED连接")
        
        total_lines = len(established_lines)
        for index, line in enumerate(established_lines):
            columns = line.split()
            if len(columns) >= 3:
                foreign_address = columns[2]  # 外部地址通常是第三列
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', foreign_address)
                if ip_match:
                    ip = ip_match.group(1)
                    # 过滤本地IP
                    if not self._is_local_ip(ip):
                        ip_addresses.append(ip)
            
            # 更新进度
            if progress_updater:
                progress = int((index + 1) / total_lines * 100)
                progress_updater.progress_signal.emit(progress)
        
        return ip_addresses
    
    def _parse_unix_connections(self, connections, progress_updater):
        """解析Linux/macOS系统的网络连接"""
        ip_addresses = []
        # 过滤已建立的连接
        established_lines = []
        
        for line in connections:
            # 在Linux/macOS中，ESTABLISHED状态可能显示为ESTAB
            if 'ESTAB' in line or 'ESTABLISHED' in line:
                established_lines.append(line)
        
        self.logger.debug(f"找到 {len(established_lines)} 个已建立连接")
        
        total_lines = len(established_lines)
        for index, line in enumerate(established_lines):
            # 解析连接行，提取远程地址
            parts = line.split()
            if len(parts) >= 5:
                # 在ss/netstat输出中，远程地址通常是第5列
                remote_addr = parts[4]
                # 提取IP地址（可能包含端口号）
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+):\d+', remote_addr)
                if ip_match:
                    ip = ip_match.group(1)
                    # 过滤本地IP
                    if not self._is_local_ip(ip):
                        ip_addresses.append(ip)
            
            # 更新进度
            if progress_updater:
                progress = int((index + 1) / total_lines * 100)
                progress_updater.progress_signal.emit(progress)
        
        return ip_addresses
    
    def _is_local_ip(self, ip):
        """检查是否为本地IP地址"""
        # 本地回环地址
        if ip.startswith('127.'):
            return True
        # 私有网络地址
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            # 检查172.16.x.x - 172.31.x.x
            if ip.startswith('172.'):
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
        # 链路本地地址
        if ip.startswith('169.254.'):
            return True
        # 多播地址
        if ip.startswith('224.') or ip.startswith('239.'):
            return True
        
        return False


def list_established_ips(progress_updater=None):
    """
    跨平台IP地址提取函数
    兼容Windows、Linux和macOS系统
    """
    try:
        extractor = IPExtractor()
        ip_addresses = extractor.extract_external_ips(progress_updater)
        
        # 去重
        unique_ips = list(set(ip_addresses))
        extractor.logger.debug(f"提取到 {len(ip_addresses)} 个IP地址，去重后得到 {len(unique_ips)} 个唯一外部IP")
        
        # 保存到文件
        ip_file_path = os.path.join(os.path.dirname(__file__), 'ips.txt')
        with open(ip_file_path, 'w') as f:
            for ip in unique_ips:
                f.write(ip + '\n')
        
        log_ip_extraction(len(unique_ips), ip_file_path)
        return unique_ips
        
    except Exception as e:
        log_error(f"发生错误: {e}", "IP提取")
        print(f"发生错误: {e}")
        return []


if __name__ == "__main__":
    # 测试跨平台IP提取
    print(f"当前系统: {platform.system()}")
    ips = list_established_ips()
    print(f"提取到的外部IP地址: {ips}")