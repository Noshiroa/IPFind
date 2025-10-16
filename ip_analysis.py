import requests
import csv
import time
from datetime import datetime
import os
from PyQt5.QtCore import pyqtSignal, QObject
from logger import get_logger, log_api_request, log_error

class ProgressUpdater(QObject):
    progress_signal = pyqtSignal(int)

def query_virustotal_ip(apikey, ip_list, output_file, progress_updater=None):
    """
    批量查询VirusTotal IP分析数据并保存为CSV文件
    :param apikey: VirusTotal API密钥
    :param ip_list: IP地址列表
    :param output_file: 输出的CSV文件路径
    """
    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {
        "x-apikey": apikey,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    # CSV文件头部 - 包含v3 API所有重要字段
    csv_headers = [
        "IP地址", "威胁等级", "恶意检测数", "可疑检测数", "无害检测数", "未检测数", "总引擎数",
        "主要恶意分类", "标签", "声誉分数", "国家", "自治系统(ASN)", "网络运营商",
        "IP网段", "最后分析时间", "记录创建时间", "大洲", "威胁分类统计"
    ]

    results = {}
    
    total_ips = len(ip_list)
    get_logger().info(f"开始批量查询 {total_ips} 个IP地址的威胁情报")
    
    for index, ip in enumerate(ip_list):
        try:
            get_logger().debug(f"正在查询IP地址: {ip}")
            # 构建完整的URL
            full_url = url + ip
            
            response = requests.get(full_url, headers=headers)
            
            # 检查API限制
            if response.status_code == 429:
                log_api_request(ip, 429)
                continue
            elif response.status_code == 401:
                log_api_request(ip, 401)
                break
            elif response.status_code == 404:
                log_api_request(ip, 404)
                continue
            elif response.status_code != 200:
                log_api_request(ip, response.status_code)
                continue
            
            data = response.json()
            
            if "data" in data:
                results[ip] = data["data"]
                # 计算恶意检测数用于日志
                attributes = data["data"].get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                log_api_request(ip, 200, malicious_count)
            else:
                get_logger().warning(f"未找到数据，IP: {ip}")
                continue
            
            # VirusTotal API限制：4次/分钟，需要控制请求频率
            time.sleep(15)  # 免费API限制较严格
            
            # 更新进度
            if progress_updater:
                progress = int((index + 1) / total_ips * 100)
                progress_updater.progress_signal.emit(progress)
                
        except Exception as e:
            log_error(f"请求失败，IP: {ip}, 错误: {e}", "API查询")
    
    # 写入CSV文件
    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)
        
        for ip, record in results.items():
            try:
                # 提取威胁情报数据
                attributes = record.get("attributes", {})
                
                # 恶意检测统计 - v3 API核心字段
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                undetected = last_analysis_stats.get("undetected", 0)
                harmless = last_analysis_stats.get("harmless", 0)
                total_engines = malicious + suspicious + undetected + harmless
                
                # 确定威胁等级
                if malicious >= 10:
                    threat_level = "🔴 高危"
                elif malicious >= 3:
                    threat_level = "🟡 中危"
                elif malicious > 0:
                    threat_level = "🟠 低危"
                else:
                    threat_level = "🟢 安全"
                
                # 恶意分类详情
                last_analysis_results = attributes.get("last_analysis_results", {})
                malicious_categories = []
                for engine, result in last_analysis_results.items():
                    category = result.get("category")
                    if category in ["malicious", "suspicious"]:
                        threat_name = result.get("result", "Unknown")
                        if threat_name and threat_name not in malicious_categories:
                            malicious_categories.append(threat_name)
                malicious_categories_str = ", ".join(malicious_categories[:8]) if malicious_categories else "无"
                
                # 威胁分类统计
                popular_threats = attributes.get("popular_threat_classification", {})
                threat_stats = []
                if popular_threats:
                    for category, data in popular_threats.get("suggested_threat_label", []):
                        threat_stats.append(f"{category}:{len(data)}")
                threat_stats_str = "; ".join(threat_stats) if threat_stats else "无"
                
                # 地理位置和网络信息
                country = attributes.get("country", "N/A")
                continent = attributes.get("continent", "N/A")
                as_owner = attributes.get("as_owner", "N/A")
                asn = attributes.get("asn", "N/A")
                network = attributes.get("network", "N/A")
                
                # 时间信息处理
                last_analysis_time = attributes.get("last_analysis_date", 0)
                if last_analysis_time:
                    last_analysis_time = datetime.fromtimestamp(last_analysis_time).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_analysis_time = "N/A"
                
                creation_time = attributes.get("creation_date", 0)
                if creation_time:
                    creation_time = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    creation_time = "N/A"
                
                # 声誉和标签信息
                reputation = attributes.get("reputation", 0)
                tags = ", ".join(attributes.get("tags", [])) if attributes.get("tags") else "无"
                
                # 写入行数据
                row = [
                    ip,
                    threat_level,
                    malicious,
                    suspicious,
                    harmless,
                    undetected,
                    total_engines,
                    malicious_categories_str,
                    tags,
                    reputation,
                    country,
                    asn,
                    as_owner,
                    network,
                    last_analysis_time,
                    creation_time,
                    continent,
                    threat_stats_str
                ]
                writer.writerow(row)
                print(f"已处理IP: {ip} - 威胁等级: {threat_level} - 恶意检测: {malicious}/{total_engines}")
                
            except Exception as e:
                print(f"处理IP数据失败: {ip}, 错误: {e}")
                continue

def query_virustotal_ip_reputation(apikey, ip_list, output_file, progress_updater=None):
    """
    简化版：只查询IP声誉信息的函数
    """
    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {
        "x-apikey": apikey,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    csv_headers = [
        "IP地址", "声誉分数", "恶意检测数", "可疑检测数", "无害检测数", "总引擎数", 
        "国家", "网络运营商", "ASN编号", "最后分析时间"
    ]
    
    results = {}
    total_ips = len(ip_list)
    
    for index, ip in enumerate(ip_list):
        try:
            print(f"查询IP声誉: {ip}")
            full_url = url + ip
            response = requests.get(full_url, headers=headers)
            
            if response.status_code == 429:
                print(f"API额度不足: {ip}")
                continue
            elif response.status_code == 401:
                print("API密钥无效")
                break
            elif response.status_code != 200:
                print(f"查询失败: {ip}, 状态码: {response.status_code}")
                continue
                
            data = response.json()
            if "data" in data:
                results[ip] = data["data"]
            
            # 遵守API限制
            time.sleep(15)
            
            if progress_updater:
                progress = int((index + 1) / total_ips * 100)
                progress_updater.progress_signal.emit(progress)
                
        except Exception as e:
            print(f"请求异常: {ip}, 错误: {e}")
    
    # 写入CSV
    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)
        
        for ip, record in results.items():
            attributes = record.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            row = [
                ip,
                attributes.get("reputation", 0),
                stats.get("malicious", 0),
                stats.get("suspicious", 0),
                stats.get("harmless", 0),
                sum(stats.values()),
                attributes.get("country", "N/A"),
                attributes.get("as_owner", "N/A"),
                attributes.get("asn", "N/A"),
                datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get("last_analysis_date") else "N/A"
            ]
            writer.writerow(row)
            print(f"已处理声誉查询: {ip}")

def get_api_usage(apikey):
    """
    查询API使用情况
    """
    url = "https://www.virustotal.com/api/v3/users/{user_id}/overall_quotas"
    headers = {
        "x-apikey": apikey,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print("API使用情况:", data)
        else:
            print(f"无法获取API使用情况，状态码: {response.status_code}")
    except Exception as e:
        print(f"查询API使用情况失败: {e}")

if __name__ == "__main__":
    # 从文件读取IP列表
    ip_file = 'ips.txt'
    if not os.path.exists(ip_file):
        print(f"错误: IP列表文件 {ip_file} 不存在")
        exit(1)
        
    with open(ip_file, 'r') as f:
        input_ips = [line.strip() for line in f.readlines() if line.strip()]
    
    if not input_ips:
        print("错误: IP列表为空")
        exit(1)
    
    # 替换为你的VirusTotal API密钥
    api_key = "YOUR_VIRUSTOTAL_API_KEY"  # 需要替换为有效的API密钥
    
    if api_key == "YOUR_VIRUSTOTAL_API_KEY":
        print("错误: 请先设置有效的VirusTotal API密钥")
        exit(1)
    
    # 生成输出文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_csv = os.path.join(os.path.dirname(__file__), f"virustotal_ip_results_{timestamp}.csv")
    
    # 调用查询函数
    print(f"开始查询 {len(input_ips)} 个IP地址...")
    print("注意: 由于API限制，查询可能需要较长时间")
    
    start_time = time.time()
    query_virustotal_ip(api_key, input_ips, output_csv)
    end_time = time.time()
    
    print(f"查询完成，耗时: {end_time - start_time:.2f} 秒")
    print(f"结果已保存到: {output_csv}")
    
    # 显示API限制信息
    print("\n=== VirusTotal API 限制信息 ===")
    print("免费账户限制: 4次/分钟, 500次/天")
    print("企业账户限制: 更高频率和额度")
    print("建议: 合理规划查询时间，避免触发限制")