import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QProgressBar, QWidget, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# 导入本地模块
sys.path.insert(0, current_dir)
from ip_extractor import list_established_ips
from ip_selection import select_ips_from_file
from ip_analysis import query_virustotal_ip as query_ip_analysis
from display_results import ResultsWindow
from config_manager import get_api_key_with_prompt
from logger import get_logger, log_operation_start, log_operation_end, log_error


class ProgressUpdater(QObject):
    """进度更新器"""
    progress_signal = pyqtSignal(int)


class ManualIPAnalysisThread(QThread):
    """手动IP分析线程 - 处理手动添加的IP分析"""
    finished_signal = pyqtSignal(str)  # 完成信号
    error_signal = pyqtSignal(str)     # 错误信号
    
    def __init__(self, progress_updater, api_key, ips):
        super().__init__()
        self.progress_updater = progress_updater
        self.api_key = api_key
        self.ips = ips
    
    def run(self):
        """运行手动IP分析任务"""
        try:
            log_operation_start("手动IP分析任务")
            get_logger().info(f"开始分析 {len(self.ips)} 个手动添加的IP地址")
            
            # 直接分析手动输入的IP地址
            output_csv = os.path.join(current_dir, 'output.csv')
            
            # 创建新的进度更新器用于IP分析
            from ip_analysis import ProgressUpdater as IPAnalysisProgressUpdater
            ip_analysis_progress_updater = IPAnalysisProgressUpdater()
            ip_analysis_progress_updater.progress_signal.connect(self.progress_updater.progress_signal.emit)
            
            # 调用IP分析函数
            query_ip_analysis(self.api_key, self.ips, output_csv, ip_analysis_progress_updater)
            
            log_operation_end("手动IP分析任务", success=True, details=f"共处理 {len(self.ips)} 个IP")
            
            # 发送完成信号
            self.finished_signal.emit(output_csv)
            
        except Exception as e:
            error_msg = f"手动IP分析过程中发生错误: {e}"
            log_error(error_msg, "手动IP分析任务")
            self.error_signal.emit(f"手动IP分析失败: {str(e)}")

class IPFindThread(QThread):
    """IP查找线程 - 处理完整的IP分析流程"""
    finished_signal = pyqtSignal(str)  # 完成信号
    selection_signal = pyqtSignal()    # 选择信号
    error_signal = pyqtSignal(str)     # 错误信号
    
    def __init__(self, progress_updater, api_key):
        super().__init__()
        self.progress_updater = progress_updater
        self.wait_for_selection = False
        self.selected_ips = []
        self.api_key = api_key

    def run(self):
        """运行完整的IP分析任务"""
        try:
            log_operation_start("IP分析任务")
            
            # 步骤1: 提取IP地址
            log_operation_start("IP地址提取")
            list_established_ips(self.progress_updater)
            log_operation_end("IP地址提取", success=True)
            
            # 发送选择信号
            self.selection_signal.emit()
            
            # 等待用户选择完成
            self.wait_for_selection = True
            while self.wait_for_selection:
                QThread.msleep(100)
            
            if not self.selected_ips:
                log_operation_end("IP分析任务", success=False, details="用户取消了IP选择")
                return
            
            # 步骤2: 查询选中的IP分析
            output_csv = os.path.join(current_dir, 'output.csv')
            input_ips = self.selected_ips
            
            log_operation_start("IP威胁情报查询")
            get_logger().info(f"开始查询 {len(input_ips)} 个IP地址的威胁情报")
            
            # 创建新的进度更新器用于IP分析
            from ip_analysis import ProgressUpdater as IPAnalysisProgressUpdater
            ip_analysis_progress_updater = IPAnalysisProgressUpdater()
            ip_analysis_progress_updater.progress_signal.connect(self.progress_updater.progress_signal.emit)
            
            query_ip_analysis(self.api_key, input_ips, output_csv, ip_analysis_progress_updater)
            
            log_operation_end("IP威胁情报查询", success=True, details=f"结果保存到: {output_csv}")
            log_operation_end("IP分析任务", success=True, details=f"共处理 {len(input_ips)} 个IP")
            
            # 发送完成信号
            self.finished_signal.emit(output_csv)
            
        except Exception as e:
            error_msg = f"IP分析过程中发生错误: {e}"
            log_error(error_msg, "IP分析任务")
            self.error_signal.emit(f"IP分析失败: {str(e)}")


class IPFindWindow(QMainWindow):
    """IP查找工具主窗口"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP查找工具")
        self.setGeometry(300, 300, 1000, 800)  # 增大窗口尺寸
        
        # 初始化变量
        self.ip_find_thread = None
        
        # 设置样式
        self.setup_style()
        
        # 创建UI
        self.setup_ui()

    def setup_style(self):
        """设置应用样式 - 使用不同的风格"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #1a1a2e, stop: 1 #16213e);
            }
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #3498db, stop: 1 #2980b9);
                border: 2px solid #2980b9;
                color: #ffffff;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
                min-width: 150px;
                min-height: 40px;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #5dade2, stop: 1 #3498db);
                border: 2px solid #3498db;
            }
            QPushButton:pressed {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #2471a3, stop: 1 #1b4f72);
                border: 2px solid #1b4f72;
            }
            QPushButton:disabled {
                background: #95a5a6;
                border: 2px solid #7f8c8d;
                color: #bdc3c7;
            }
            QLabel {
                color: #ffffff;
                background: transparent;
                font-weight: bold;
            }
            QProgressBar {
                border: 2px solid #34495e;
                border-radius: 5px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
                background: #2c3e50;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                          stop: 0 #e74c3c, stop: 0.5 #e67e22, stop: 1 #f1c40f);
                border-radius: 3px;
            }
        """)

    def setup_ui(self):
        """设置用户界面"""
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignTop)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # 添加标题
        title_label = QLabel("IP查找工具")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            color: #ffffff;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                      stop: 0 #e74c3c, stop: 0.5 #e67e22, stop: 1 #f1c40f);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 2px solid #ffffff;
        """)
        main_layout.addWidget(title_label)

        # 添加描述
        description_label = QLabel(
            "本工具用于分析系统的网络连接，提取外部IP地址并进行威胁情报查询。\n"
            "点击下方按钮开始分析。"
        )
        description_label.setFont(QFont("Arial", 12, QFont.Bold))
        description_label.setAlignment(Qt.AlignCenter)
        description_label.setStyleSheet("""
            color: #ffffff;
            background-color: rgba(52, 152, 219, 0.8);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 30px;
            line-height: 1.5;
            border: 1px solid #3498db;
        """)
        description_label.setWordWrap(True)
        main_layout.addWidget(description_label)

        # 按钮布局
        button_layout = QHBoxLayout()
        
        # 添加开始按钮
        self.start_button = QPushButton("开始IP分析")
        self.start_button.clicked.connect(self.start_analysis)
        button_layout.addWidget(self.start_button)
        
        # 添加手动输入IP按钮
        self.manual_ip_button = QPushButton("手动添加IP")
        self.manual_ip_button.clicked.connect(self.manual_add_ips)
        button_layout.addWidget(self.manual_ip_button)
        
        main_layout.addLayout(button_layout)

        # 添加进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("margin-top: 30px; height: 25px;")
        main_layout.addWidget(self.progress_bar)

        # 添加状态标签
        self.status_label = QLabel("状态: 等待开始")
        self.status_label.setFont(QFont("Arial", 12, QFont.Bold))
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            background-color: rgba(41, 128, 185, 0.9);
            color: #ffffff;
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #ffffff;
            font-weight: bold;
        """)
        main_layout.addWidget(self.status_label)

        # 设置中心窗口
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)

    def update_status(self, message, is_error=False):
        """更新状态信息"""
        color = "#e74c3c" if is_error else "#2ecc71"
        self.status_label.setText(f"状态: {message}")
        self.status_label.setStyleSheet(f"""
            background-color: rgba(52, 73, 94, 0.8);
            color: {color};
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #3498db;
            font-weight: bold;
        """)

    def start_analysis(self):
        """开始IP分析"""
        # 先获取API密钥（在主线程中）
        api_key = get_api_key_with_prompt(self)
        if not api_key:
            self.update_status("未设置API密钥，操作已取消", True)
            return
        
        self.start_button.setEnabled(False)
        self.update_status("正在启动IP分析...")
        self.progress_bar.setValue(0)

        # 创建进度更新器
        progress_updater = ProgressUpdater()
        progress_updater.progress_signal.connect(self.update_progress)

        # 启动IP查找线程
        self.ip_find_thread = IPFindThread(progress_updater, api_key)
        self.ip_find_thread.finished_signal.connect(self.show_results)
        self.ip_find_thread.selection_signal.connect(self.show_ip_selection)
        self.ip_find_thread.error_signal.connect(self.handle_error)
        self.ip_find_thread.start()

        self.update_status("IP分析已启动，请稍候...")

    def show_ip_selection(self):
        """显示IP选择对话框"""
        try:
            ip_file_path = os.path.join(current_dir, 'ips.txt')
            selected_ips = select_ips_from_file(ip_file_path)
            
            if selected_ips:
                self.ip_find_thread.selected_ips = selected_ips
                self.ip_find_thread.wait_for_selection = False
                self.update_status(f"已选择 {len(selected_ips)} 个IP进行查询")
            else:
                self.ip_find_thread.selected_ips = []
                self.ip_find_thread.wait_for_selection = False
                self.update_status("用户取消了IP选择")
                self.start_button.setEnabled(True)
                
        except Exception as e:
            self.update_status(f"IP选择失败: {str(e)}", True)
            print(f"IP选择错误: {e}")
            self.ip_find_thread.selected_ips = []
            self.ip_find_thread.wait_for_selection = False
            self.start_button.setEnabled(True)

    def handle_error(self, error_message):
        """处理错误信号"""
        self.update_status(error_message, True)
        self.start_button.setEnabled(True)

    def show_results(self, output_csv):
        """显示分析结果"""
        try:
            self.result_window = ResultsWindow(output_csv)
            self.result_window.show()
            self.update_status("IP分析完成，结果窗口已显示")
            self.start_button.setEnabled(True)
            self.manual_ip_button.setEnabled(True)
        except Exception as e:
            self.update_status(f"显示结果失败: {str(e)}", True)
            print(f"显示结果错误: {e}")
            self.start_button.setEnabled(True)
            self.manual_ip_button.setEnabled(True)

    def manual_add_ips(self):
        """手动添加IP地址进行分析"""
        from PyQt5.QtWidgets import QInputDialog, QMessageBox
        import re
        
        # 获取API密钥
        api_key = get_api_key_with_prompt(self)
        if not api_key:
            self.update_status("未设置API密钥，操作已取消", True)
            return
        
        # 显示输入对话框
        text, ok = QInputDialog.getMultiLineText(
            self,
            "手动添加IP地址",
            "请输入要分析的IP地址（每行一个）：",
            "8.8.8.8\n1.1.1.1\n192.168.1.1"
        )
        
        # 设置输入对话框样式
        for dialog in self.findChildren(QInputDialog):
            dialog.setStyleSheet("""
                QInputDialog {
                    background-color: #1a1a2e;
                    color: #ffffff;
                }
                QInputDialog QLabel {
                    color: #ffffff;
                    font-weight: bold;
                    font-size: 12px;
                }
                QInputDialog QTextEdit, QInputDialog QLineEdit {
                    background-color: #2c3e50;
                    color: #ffffff;
                    border: 2px solid #3498db;
                    border-radius: 4px;
                    padding: 8px;
                    font-size: 12px;
                }
                QInputDialog QPushButton {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                              stop: 0 #3498db, stop: 1 #2980b9);
                    border: 2px solid #2980b9;
                    color: #ffffff;
                    padding: 8px 16px;
                    font-size: 12px;
                    font-weight: bold;
                    border-radius: 6px;
                    min-width: 80px;
                    min-height: 30px;
                }
                QInputDialog QPushButton:hover {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                              stop: 0 #5dade2, stop: 1 #3498db);
                    border: 2px solid #3498db;
                }
            """)
        
        if ok and text:
            # 解析输入的IP地址
            ips = [ip.strip() for ip in text.split('\n') if ip.strip()]
            valid_ips = []
            invalid_ips = []
            
            # 验证IP地址格式
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            for ip in ips:
                if ip_pattern.match(ip):
                    # 检查每个部分是否在0-255范围内
                    parts = ip.split('.')
                    if all(0 <= int(part) <= 255 for part in parts):
                        valid_ips.append(ip)
                    else:
                        invalid_ips.append(ip)
                else:
                    invalid_ips.append(ip)
            
            if not valid_ips:
                # 设置警告对话框样式
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle("输入错误")
                msg_box.setText("没有有效的IP地址")
                msg_box.setIcon(QMessageBox.Warning)
                msg_box.setStyleSheet("""
                    QMessageBox {
                        background-color: #1a1a2e;
                        color: #ffffff;
                        font-weight: bold;
                    }
                    QMessageBox QLabel {
                        color: #ffffff;
                        font-weight: bold;
                        font-size: 12px;
                    }
                    QMessageBox QPushButton {
                        background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                  stop: 0 #3498db, stop: 1 #2980b9);
                        border: 2px solid #2980b9;
                        color: #ffffff;
                        padding: 8px 16px;
                        font-size: 12px;
                        font-weight: bold;
                        border-radius: 6px;
                        min-width: 80px;
                        min-height: 30px;
                    }
                """)
                msg_box.exec_()
                return
            
            # 显示确认对话框
            message = f"将分析以下 {len(valid_ips)} 个IP地址:\n\n" + "\n".join(valid_ips)
            if invalid_ips:
                message += f"\n\n以下IP地址格式无效:\n" + "\n".join(invalid_ips)
            
            # 设置确认对话框样式
            confirm_box = QMessageBox(self)
            confirm_box.setWindowTitle("确认分析")
            confirm_box.setText(message + "\n\n是否继续分析？")
            confirm_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            confirm_box.setDefaultButton(QMessageBox.Yes)
            confirm_box.setStyleSheet("""
                QMessageBox {
                    background-color: #1a1a2e;
                    color: #ffffff;
                    font-weight: bold;
                }
                QMessageBox QLabel {
                    color: #ffffff;
                    font-weight: bold;
                    font-size: 12px;
                }
                QMessageBox QPushButton {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                              stop: 0 #3498db, stop: 1 #2980b9);
                    border: 2px solid #2980b9;
                    color: #ffffff;
                    padding: 8px 16px;
                    font-size: 12px;
                    font-weight: bold;
                    border-radius: 6px;
                    min-width: 80px;
                    min-height: 30px;
                }
                QMessageBox QPushButton:hover {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                              stop: 0 #5dade2, stop: 1 #3498db);
                    border: 2px solid #3498db;
                }
            """)
            
            reply = confirm_box.exec_()
            
            if reply == QMessageBox.Yes:
                self.start_button.setEnabled(False)
                self.manual_ip_button.setEnabled(False)
                self.update_status(f"开始分析 {len(valid_ips)} 个手动添加的IP地址")
                self.progress_bar.setValue(0)
                
                # 启动分析线程
                self.analyze_manual_ips(api_key, valid_ips)
            else:
                self.update_status("用户取消了手动IP分析")

    def analyze_manual_ips(self, api_key, ips):
        """分析手动添加的IP地址"""
        try:
            # 创建进度更新器
            progress_updater = ProgressUpdater()
            progress_updater.progress_signal.connect(self.update_progress)
            
            # 启动分析线程
            self.manual_ip_thread = ManualIPAnalysisThread(progress_updater, api_key, ips)
            self.manual_ip_thread.finished_signal.connect(self.show_results)
            self.manual_ip_thread.error_signal.connect(self.handle_error)
            self.manual_ip_thread.start()
            
            self.update_status("手动IP分析已启动，请稍候...")
            
        except Exception as e:
            self.update_status(f"启动手动IP分析失败: {str(e)}", True)
            self.start_button.setEnabled(True)
            self.manual_ip_button.setEnabled(True)

    def closeEvent(self, event):
        """关闭应用时的确认对话框"""
        # 创建自定义样式的消息框
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle('确认退出')
        msg_box.setText('确定要退出IP查找工具吗？')
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        
        # 设置消息框样式
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a2e;
                color: #ffffff;
                font-weight: bold;
            }
            QMessageBox QLabel {
                color: #ffffff;
                font-weight: bold;
                font-size: 12px;
            }
            QMessageBox QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #3498db, stop: 1 #2980b9);
                border: 2px solid #2980b9;
                color: #ffffff;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
                min-width: 80px;
                min-height: 30px;
            }
            QMessageBox QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #5dade2, stop: 1 #3498db);
                border: 2px solid #3498db;
            }
        """)
        
        reply = msg_box.exec_()

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


def main():
    """IP查找工具主函数"""
    app = QApplication(sys.argv)
    
    # 设置应用属性
    app.setApplicationName("IP查找工具")
    app.setApplicationVersion("1.0.0")
    
    window = IPFindWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
