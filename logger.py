import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler


class IPFindLogger:
    """IPFind工具日志管理器"""
    
    def __init__(self, log_dir=None):
        """
        初始化日志管理器
        
        Args:
            log_dir: 日志文件目录，默认为IPFind目录下的logs文件夹
        """
        if log_dir is None:
            self.log_dir = os.path.join(os.path.dirname(__file__), 'logs')
        else:
            self.log_dir = log_dir
        
        # 创建日志目录
        os.makedirs(self.log_dir, exist_ok=True)
        
        # 配置日志
        self.setup_logging()
    
    def setup_logging(self):
        """配置日志系统"""
        # 创建logger
        self.logger = logging.getLogger('IPFind')
        self.logger.setLevel(logging.DEBUG)
        
        # 避免重复添加handler
        if self.logger.handlers:
            return
        
        # 日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 文件处理器 - 按天轮转，保留7天
        log_file = os.path.join(self.log_dir, 'ipfind.log')
        file_handler = TimedRotatingFileHandler(
            log_file,
            when='midnight',
            interval=1,
            backupCount=7,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # 添加处理器
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message):
        """记录调试信息"""
        self.logger.debug(message)
    
    def info(self, message):
        """记录一般信息"""
        self.logger.info(message)
    
    def warning(self, message):
        """记录警告信息"""
        self.logger.warning(message)
    
    def error(self, message):
        """记录错误信息"""
        self.logger.error(message)
    
    def critical(self, message):
        """记录严重错误信息"""
        self.logger.critical(message)
    
    def log_operation_start(self, operation_name):
        """记录操作开始"""
        self.info(f"开始操作: {operation_name}")
    
    def log_operation_end(self, operation_name, success=True, details=""):
        """记录操作结束"""
        status = "成功" if success else "失败"
        message = f"操作完成: {operation_name} - {status}"
        if details:
            message += f" - {details}"
        
        if success:
            self.info(message)
        else:
            self.error(message)
    
    def log_api_request(self, ip_address, status_code, result_count=0):
        """记录API请求信息"""
        if status_code == 200:
            self.info(f"API查询成功 - IP: {ip_address} - 结果数: {result_count}")
        elif status_code == 429:
            self.warning(f"API额度不足 - IP: {ip_address}")
        elif status_code == 401:
            self.error(f"API密钥无效 - IP: {ip_address}")
        elif status_code == 404:
            self.warning(f"IP地址未找到 - IP: {ip_address}")
        else:
            self.error(f"API请求失败 - IP: {ip_address} - 状态码: {status_code}")
    
    def log_ip_extraction(self, ip_count, file_path):
        """记录IP提取信息"""
        self.info(f"提取到 {ip_count} 个唯一IP地址 - 保存到: {file_path}")
    
    def log_error(self, error_message, operation_name=""):
        """记录错误信息"""
        if operation_name:
            self.error(f"{operation_name} - 错误: {error_message}")
        else:
            self.error(f"错误: {error_message}")


# 全局日志实例
_logger_instance = None


def get_logger():
    """获取全局日志实例"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = IPFindLogger()
    return _logger_instance


# 便捷函数
def debug(message):
    get_logger().debug(message)

def info(message):
    get_logger().info(message)

def warning(message):
    get_logger().warning(message)

def error(message):
    get_logger().error(message)

def critical(message):
    get_logger().critical(message)

def log_operation_start(operation_name):
    get_logger().log_operation_start(operation_name)

def log_operation_end(operation_name, success=True, details=""):
    get_logger().log_operation_end(operation_name, success, details)

def log_api_request(ip_address, status_code, result_count=0):
    get_logger().log_api_request(ip_address, status_code, result_count)

def log_ip_extraction(ip_count, file_path):
    get_logger().log_ip_extraction(ip_count, file_path)

def log_error(error_message, operation_name=""):
    get_logger().log_error(error_message, operation_name)


if __name__ == "__main__":
    # 测试日志功能
    logger = get_logger()
    logger.info("日志系统测试开始")
    logger.debug("这是一条调试信息")
    logger.info("这是一条普通信息")
    logger.warning("这是一条警告信息")
    logger.error("这是一条错误信息")
    logger.log_operation_start("测试操作")
    logger.log_operation_end("测试操作", success=True, details="耗时: 1.2秒")
    logger.log_api_request("8.8.8.8", 200, 5)
    logger.log_ip_extraction(10, "ips.txt")
    logger.info("日志系统测试完成")