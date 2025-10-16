import os
import json
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from logger import get_logger


class ConfigManager:
    """配置管理器 - 负责管理API密钥等配置信息"""
    
    def __init__(self, config_file=None):
        if config_file is None:
            # 默认在IPFind目录下创建配置文件
            self.config_file = os.path.join(os.path.dirname(__file__), 'config.json')
        else:
            self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    get_logger().debug("配置文件加载成功")
                    return config
            except Exception as e:
                get_logger().error(f"加载配置文件失败: {e}")
                return {}
        get_logger().debug("配置文件不存在，返回空配置")
        return {}
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            get_logger().debug("配置文件保存成功")
            return True
        except Exception as e:
            get_logger().error(f"保存配置文件失败: {e}")
            return False
    
    def get_api_key(self):
        """获取API密钥"""
        api_key = self.config.get('api_key', '')
        if api_key:
            get_logger().debug("API密钥已从配置文件中获取")
        else:
            get_logger().debug("配置文件中未找到API密钥")
        return api_key
    
    def set_api_key(self, api_key):
        """设置API密钥"""
        self.config['api_key'] = api_key
        success = self.save_config()
        if success:
            get_logger().info("API密钥已成功保存到配置文件")
        else:
            get_logger().error("API密钥保存失败")
        return success
    
    def is_api_key_set(self):
        """检查API密钥是否已设置"""
        is_set = bool(self.get_api_key())
        get_logger().debug(f"API密钥设置状态: {'已设置' if is_set else '未设置'}")
        return is_set


class ApiKeyDialog(QDialog):
    """API密钥输入对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置API密钥")
        self.setModal(True)
        self.setFixedSize(400, 200)
        
        self.api_key = ""
        self.setup_ui()
    
    def setup_ui(self):
        """设置对话框UI"""
        layout = QVBoxLayout()
        
        # 说明文字
        info_label = QLabel(
            "首次使用需要设置VirusTotal API密钥。\n"
            "请访问 https://www.virustotal.com/ 注册账号并获取API密钥。"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # API密钥输入框
        api_layout = QHBoxLayout()
        api_label = QLabel("API密钥:")
        self.api_input = QLineEdit()
        self.api_input.setPlaceholderText("请输入您的VirusTotal API密钥")
        self.api_input.setEchoMode(QLineEdit.Password)
        api_layout.addWidget(api_label)
        api_layout.addWidget(self.api_input)
        layout.addLayout(api_layout)
        
        # 按钮布局
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("确定")
        self.cancel_button = QPushButton("取消")
        
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def accept(self):
        """确认输入"""
        api_key = self.api_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "输入错误", "请输入API密钥")
            return
        
        self.api_key = api_key
        super().accept()


def get_api_key_with_prompt(parent=None):
    """
    获取API密钥，如果未设置则提示用户输入
    
    Args:
        parent: 父窗口
        
    Returns:
        str: API密钥，如果用户取消则为空字符串
    """
    config_manager = ConfigManager()
    
    # 如果已设置API密钥，直接返回
    if config_manager.is_api_key_set():
        return config_manager.get_api_key()
    
    # 显示API密钥输入对话框
    dialog = ApiKeyDialog(parent)
    if dialog.exec_() == QDialog.Accepted:
        api_key = dialog.api_key
        if api_key:
            config_manager.set_api_key(api_key)
            QMessageBox.information(parent, "设置成功", "API密钥已保存，下次使用时无需再次输入。")
            return api_key
    
    return ""