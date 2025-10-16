#!/usr/bin/env python3
"""
IPFind CLI - Linux命令行版本的IP威胁情报分析工具
跨平台兼容：Windows、Linux、macOS
"""

import os
import sys
import argparse
import platform
from datetime import datetime

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from ip_extractor import list_established_ips
from ip_analysis import query_virustotal_ip
from config_manager import ConfigManager
from logger import get_logger


class IPFindCLI:
    """IPFind命令行工具"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.logger = get_logger()
        self.config_manager = ConfigManager()
    
    def setup_argparse(self):
        """设置命令行参数解析"""
        parser = argparse.ArgumentParser(
            description='IPFind - 跨平台IP威胁情报分析工具',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
使用示例:
  # 自动提取并分析网络连接中的外部IP
  python ipfind_cli.py --auto
  
  # 手动指定IP列表文件进行分析
  python ipfind_cli.py --input ips.txt
  
  # 手动输入IP地址进行分析
  python ipfind_cli.py --ips "8.8.8.8,1.1.1.1"
  
  # 设置API密钥
  python ipfind_cli.py --set-api-key YOUR_API_KEY
  
  # 检查API密钥状态
  python ipfind_cli.py --check-api-key
  
  # 显示详细输出
  python ipfind_cli.py --auto --verbose
            """
        )
        
        # 主要操作模式
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--auto', action='store_true', 
                          help='自动提取并分析网络连接中的外部IP')
        group.add_argument('--input', type=str, 
                          help='从文件读取IP列表进行分析')
        group.add_argument('--ips', type=str,
                          help='手动指定IP地址（逗号分隔）')
        group.add_argument('--set-api-key', type=str,
                          help='设置VirusTotal API密钥')
        group.add_argument('--check-api-key', action='store_true',
                          help='检查API密钥状态')
        
        # 可选参数
        parser.add_argument('--output', type=str, default='output.csv',
                          help='输出CSV文件路径（默认: output.csv）')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='显示详细输出信息')
        parser.add_argument('--no-color', action='store_true',
                          help='禁用彩色输出')
        
        return parser
    
    def print_banner(self):
        """显示工具横幅"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                   IPFind CLI - v1.0.0                        ║
║             跨平台IP威胁情报分析工具                         ║
║                   系统: {self.system.upper():<10}                    ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_colored(self, text, color_code):
        """打印彩色文本"""
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and not self.args.no_color:
            print(f"\033[{color_code}m{text}\033[0m")
        else:
            print(text)
    
    def print_success(self, text):
        """打印成功信息（绿色）"""
        self.print_colored(f"✓ {text}", "32")
    
    def print_error(self, text):
        """打印错误信息（红色）"""
        self.print_colored(f"✗ {text}", "31")
    
    def print_warning(self, text):
        """打印警告信息（黄色）"""
        self.print_colored(f"⚠ {text}", "33")
    
    def print_info(self, text):
        """打印信息（蓝色）"""
        self.print_colored(f"ℹ {text}", "34")
    
    def check_api_key(self):
        """检查API密钥状态"""
        if self.config_manager.is_api_key_set():
            api_key = self.config_manager.get_api_key()
            masked_key = api_key[:8] + "..." + api_key[-4:]
            self.print_success(f"API密钥已设置: {masked_key}")
            return True
        else:
            self.print_error("API密钥未设置，请使用 --set-api-key 参数设置")
            return False
    
    def set_api_key(self, api_key):
        """设置API密钥"""
        if self.config_manager.set_api_key(api_key):
            masked_key = api_key[:8] + "..." + api_key[-4:]
            self.print_success(f"API密钥设置成功: {masked_key}")
            return True
        else:
            self.print_error("API密钥设置失败")
            return False
    
    def extract_ips_auto(self):
        """自动提取IP地址"""
        self.print_info("开始自动提取网络连接中的外部IP地址...")
        
        try:
            ips = list_established_ips()
            if not ips:
                self.print_warning("未找到外部IP地址")
                return []
            
            self.print_success(f"成功提取到 {len(ips)} 个外部IP地址")
            if self.args.verbose:
                for i, ip in enumerate(ips, 1):
                    print(f"  {i:2d}. {ip}")
            
            return ips
            
        except Exception as e:
            self.print_error(f"提取IP地址失败: {e}")
            return []
    
    def read_ips_from_file(self, file_path):
        """从文件读取IP地址"""
        if not os.path.exists(file_path):
            self.print_error(f"文件不存在: {file_path}")
            return []
        
        try:
            with open(file_path, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            if not ips:
                self.print_warning("文件为空")
                return []
            
            self.print_success(f"从文件读取到 {len(ips)} 个IP地址")
            if self.args.verbose:
                for i, ip in enumerate(ips, 1):
                    print(f"  {i:2d}. {ip}")
            
            return ips
            
        except Exception as e:
            self.print_error(f"读取文件失败: {e}")
            return []
    
    def parse_manual_ips(self, ip_string):
        """解析手动输入的IP地址"""
        ips = [ip.strip() for ip in ip_string.split(',') if ip.strip()]
        
        if not ips:
            self.print_error("未提供有效的IP地址")
            return []
        
        # 验证IP格式
        valid_ips = []
        invalid_ips = []
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        
        for ip in ips:
            if ip_pattern.match(ip):
                parts = ip.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    valid_ips.append(ip)
                else:
                    invalid_ips.append(ip)
            else:
                invalid_ips.append(ip)
        
        if invalid_ips:
            self.print_warning(f"以下IP地址格式无效: {', '.join(invalid_ips)}")
        
        if not valid_ips:
            self.print_error("没有有效的IP地址")
            return []
        
        self.print_success(f"解析到 {len(valid_ips)} 个有效IP地址")
        if self.args.verbose:
            for i, ip in enumerate(valid_ips, 1):
                print(f"  {i:2d}. {ip}")
        
        return valid_ips
    
    def analyze_ips(self, ips):
        """分析IP地址"""
        if not ips:
            self.print_error("没有要分析的IP地址")
            return False
        
        # 检查API密钥
        if not self.check_api_key():
            return False
        
        api_key = self.config_manager.get_api_key()
        output_file = self.args.output
        
        self.print_info(f"开始分析 {len(ips)} 个IP地址...")
        self.print_info(f"输出文件: {output_file}")
        
        if self.args.verbose:
            self.print_info("注意: VirusTotal免费API限制为4次/分钟，500次/天")
            estimated_time = len(ips) * 15 / 60  # 每个IP15秒
            self.print_info(f"预计耗时: {estimated_time:.1f} 分钟")
        
        try:
            # 创建进度回调函数
            def progress_callback(progress):
                if self.args.verbose:
                    print(f"\r进度: {progress}%", end='', flush=True)
            
            # 创建进度更新器
            from PyQt5.QtCore import QObject
            class CLIProgressUpdater(QObject):
                progress_signal = pyqtSignal(int)
            
            progress_updater = CLIProgressUpdater()
            progress_updater.progress_signal.connect(progress_callback)
            
            # 执行分析
            start_time = datetime.now()
            query_virustotal_ip(api_key, ips, output_file, progress_updater)
            end_time = datetime.now()
            
            if self.args.verbose:
                print()  # 换行
            
            elapsed_time = (end_time - start_time).total_seconds()
            self.print_success(f"分析完成！耗时: {elapsed_time:.1f} 秒")
            self.print_success(f"结果已保存到: {output_file}")
            
            # 显示结果摘要
            self.show_results_summary(output_file)
            
            return True
            
        except Exception as e:
            self.print_error(f"分析失败: {e}")
            return False
    
    def show_results_summary(self, output_file):
        """显示结果摘要"""
        if not os.path.exists(output_file):
            self.print_warning("输出文件不存在")
            return
        
        try:
            import csv
            with open(output_file, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                self.print_warning("输出文件为空")
                return
            
            # 统计威胁等级
            threat_levels = {}
            for row in rows:
                level = row.get('威胁等级', '未知')
                threat_levels[level] = threat_levels.get(level, 0) + 1
            
            self.print_info("分析结果摘要:")
            for level, count in threat_levels.items():
                print(f"  {level}: {count} 个IP")
            
            # 显示高危IP
            high_risk_ips = [row for row in rows if '高危' in row.get('威胁等级', '')]
            if high_risk_ips:
                self.print_warning("发现高危IP地址:")
                for row in high_risk_ips:
                    ip = row.get('IP地址', '未知')
                    malicious = row.get('恶意检测数', '0')
                    print(f"  {ip} - 恶意检测: {malicious}")
            
        except Exception as e:
            self.print_warning(f"无法读取结果文件: {e}")
    
    def run(self):
        """运行命令行工具"""
        parser = self.setup_argparse()
        self.args = parser.parse_args()
        
        # 显示横幅
        self.print_banner()
        
        # 处理不同模式
        if self.args.set_api_key:
            self.set_api_key(self.args.set_api_key)
        
        elif self.args.check_api_key:
            self.check_api_key()
        
        elif self.args.auto:
            ips = self.extract_ips_auto()
            if ips:
                self.analyze_ips(ips)
        
        elif self.args.input:
            ips = self.read_ips_from_file(self.args.input)
            if ips:
                self.analyze_ips(ips)
        
        elif self.args.ips:
            ips = self.parse_manual_ips(self.args.ips)
            if ips:
                self.analyze_ips(ips)


def main():
    """主函数"""
    try:
        cli = IPFindCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\n操作被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()