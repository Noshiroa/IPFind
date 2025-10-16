import sys
import csv
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

class ResultsWindow(QMainWindow):
    def __init__(self, csv_file):
        super().__init__()
        self.setWindowTitle("IP分析结果")
        self.setGeometry(100, 100, 800, 600)

        # 创建表格控件
        self.table = QTableWidget()
        self.load_csv_data(csv_file)

        # 设置布局
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def load_csv_data(self, csv_file):
        """从CSV文件加载数据到表格控件中"""
        with open(csv_file, 'r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            headers = next(reader)

            # 设置表格尺寸
            self.table.setColumnCount(len(headers))
            self.table.setHorizontalHeaderLabels(headers)

            rows = list(reader)
            self.table.setRowCount(len(rows))

            for row_idx, row in enumerate(rows):
                for col_idx, cell in enumerate(row):
                    self.table.setItem(row_idx, col_idx, QTableWidgetItem(cell))

        # 自动调整列宽和行高以适应内容
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 构建正确的输出文件路径
    output_file = os.path.join(os.path.dirname(__file__), 'output.csv')
    print(f"尝试打开文件: {output_file}")
    
    if not os.path.exists(output_file):
        print(f"错误: 文件不存在 - {output_file}")
        print("请先运行IP分析脚本生成输出文件")
        sys.exit(1)
    
    window = ResultsWindow(output_file)
    window.show()

    sys.exit(app.exec_())