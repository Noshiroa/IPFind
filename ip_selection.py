import sys
import os
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout, 
                             QListWidget, QListWidgetItem, QCheckBox, QPushButton, 
                             QLabel, QMessageBox)
from PyQt5.QtCore import Qt

class IPSelectionDialog(QDialog):
    """IP选择对话框 - 让用户手动选择要查询的IP地址"""
    
    def __init__(self, ip_list, parent=None):
        super().__init__(parent)
        self.ip_list = ip_list
        self.selected_ips = []
        self.setWindowTitle("选择要查询的IP地址")
        self.setGeometry(200, 200, 400, 500)
        self.setup_ui()
        
    def setup_ui(self):
        """设置用户界面"""
        layout = QVBoxLayout()
        
        # 标题
        title_label = QLabel("请选择要查询的IP地址:")
        title_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title_label)
        
        # IP列表
        self.ip_list_widget = QListWidget()
        self.ip_list_widget.setSelectionMode(QListWidget.MultiSelection)
        
        for ip in self.ip_list:
            item = QListWidgetItem(ip)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.ip_list_widget.addItem(item)
        
        layout.addWidget(self.ip_list_widget)
        
        # 按钮布局
        button_layout = QHBoxLayout()
        
        # 全选按钮
        select_all_btn = QPushButton("全选")
        select_all_btn.clicked.connect(self.select_all)
        button_layout.addWidget(select_all_btn)
        
        # 全不选按钮
        select_none_btn = QPushButton("全不选")
        select_none_btn.clicked.connect(self.select_none)
        button_layout.addWidget(select_none_btn)
        
        # 反选按钮
        invert_btn = QPushButton("反选")
        invert_btn.clicked.connect(self.invert_selection)
        button_layout.addWidget(invert_btn)
        
        layout.addLayout(button_layout)
        
        # 确定和取消按钮
        confirm_layout = QHBoxLayout()
        
        ok_btn = QPushButton("确定")
        ok_btn.clicked.connect(self.accept_selection)
        confirm_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        confirm_layout.addWidget(cancel_btn)
        
        layout.addLayout(confirm_layout)
        
        self.setLayout(layout)
    
    def select_all(self):
        """全选所有IP"""
        for i in range(self.ip_list_widget.count()):
            item = self.ip_list_widget.item(i)
            item.setCheckState(Qt.Checked)
    
    def select_none(self):
        """全不选所有IP"""
        for i in range(self.ip_list_widget.count()):
            item = self.ip_list_widget.item(i)
            item.setCheckState(Qt.Unchecked)
    
    def invert_selection(self):
        """反选IP"""
        for i in range(self.ip_list_widget.count()):
            item = self.ip_list_widget.item(i)
            if item.checkState() == Qt.Checked:
                item.setCheckState(Qt.Unchecked)
            else:
                item.setCheckState(Qt.Checked)
    
    def accept_selection(self):
        """确认选择"""
        self.selected_ips = []
        for i in range(self.ip_list_widget.count()):
            item = self.ip_list_widget.item(i)
            if item.checkState() == Qt.Checked:
                self.selected_ips.append(item.text())
        
        if not self.selected_ips:
            QMessageBox.warning(self, "警告", "请至少选择一个IP地址进行查询！")
            return
        
        self.accept()
    
    def get_selected_ips(self):
        """获取选中的IP列表"""
        return self.selected_ips


def select_ips_from_file(ip_file_path):
    """从文件读取IP并显示选择对话框"""
    try:
        with open(ip_file_path, 'r') as f:
            ip_list = [line.strip() for line in f.readlines() if line.strip()]
        
        if not ip_list:
            QMessageBox.warning(None, "警告", "没有找到IP地址！")
            return []
        
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        
        dialog = IPSelectionDialog(ip_list)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_selected_ips()
        else:
            return []
            
    except Exception as e:
        QMessageBox.critical(None, "错误", f"读取IP文件失败: {str(e)}")
        return []


if __name__ == "__main__":
    # 测试代码
    app = QApplication(sys.argv)
    
    # 创建测试IP列表
    test_ips = ["104.24.102.50", "1.1.1.1", "192.168.1.1", "10.0.0.1"]
    
    dialog = IPSelectionDialog(test_ips)
    if dialog.exec_() == QDialog.Accepted:
        selected = dialog.get_selected_ips()
        print(f"选中的IP: {selected}")
    else:
        print("用户取消了选择")