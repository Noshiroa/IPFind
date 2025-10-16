#!/bin/bash

# IPFind Linux 安装脚本
# 适用于 Ubuntu/Debian/CentOS/RHEL 等主流Linux发行版

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印彩色信息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_info "检测到系统: $OS $VER"
}

# 检查Python是否安装
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python3 已安装: $PYTHON_VERSION"
    else
        print_error "Python3 未安装"
        return 1
    fi
}

# 检查必要的系统工具
check_system_tools() {
    local missing_tools=()
    
    # 检查网络工具
    if ! command -v ss &> /dev/null && ! command -v netstat &> /dev/null; then
        missing_tools+=("网络工具 (ss 或 netstat)")
    fi
    
    # 检查pip
    if ! command -v pip3 &> /dev/null; then
        missing_tools+=("pip3")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "缺少必要的系统工具: ${missing_tools[*]}"
        return 1
    else
        print_success "所有必要的系统工具都已安装"
    fi
}

# 安装系统依赖
install_dependencies() {
    print_info "安装系统依赖..."
    
    if command -v apt &> /dev/null; then
        # Ubuntu/Debian
        sudo apt update
        sudo apt install -y python3-pip python3-venv net-tools
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        sudo yum install -y python3-pip python3-venv net-tools
    elif command -v dnf &> /dev/null; then
        # Fedora
        sudo dnf install -y python3-pip python3-venv net-tools
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        sudo pacman -S --noconfirm python-pip python-virtualenv net-tools
    else
        print_warning "无法自动安装依赖，请手动安装: python3-pip python3-venv net-tools"
    fi
}

# 安装Python依赖
install_python_deps() {
    print_info "安装Python依赖..."
    
    # 创建虚拟环境（可选）
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "创建虚拟环境"
    fi
    
    # 激活虚拟环境
    source venv/bin/activate
    
    # 安装依赖
    pip3 install -r requirements.txt
    
    print_success "Python依赖安装完成"
}

# 创建启动脚本
create_launcher() {
    print_info "创建启动脚本..."
    
    local script_dir=$(dirname "$(readlink -f "$0")")
    
    # 创建桌面启动器
    cat > ~/.local/share/applications/ipfind.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=IPFind
Comment=跨平台IP威胁情报分析工具
Exec=python3 $script_dir/ipfind_app.py
Icon=network-wired
Terminal=false
Categories=Network;Security;
EOF
    
    # 创建命令行快捷方式
    sudo tee /usr/local/bin/ipfind > /dev/null << EOF
#!/bin/bash
cd $script_dir
source venv/bin/activate 2>/dev/null || true
python3 ipfind_cli.py "\$@"
EOF
    
    sudo chmod +x /usr/local/bin/ipfind
    
    print_success "启动脚本创建完成"
}

# 设置文件权限
set_permissions() {
    print_info "设置文件权限..."
    
    chmod +x ipfind_cli.py
    chmod +x install_linux.sh
    
    print_success "文件权限设置完成"
}

# 显示使用说明
show_usage() {
    echo
    print_success "IPFind 安装完成！"
    echo
    echo "使用方法:"
    echo "  GUI版本: python3 ipfind_app.py"
    echo "  命令行版本: ipfind --help"
    echo
    echo "常用命令示例:"
    echo "  # 自动分析网络连接"
    echo "  ipfind --auto"
    echo
    echo "  # 从文件分析IP"
    echo "  ipfind --input ips.txt"
    echo
    echo "  # 手动分析指定IP"
    echo "  ipfind --ips \"8.8.8.8,1.1.1.1\""
    echo
    echo "  # 设置API密钥"
    echo "  ipfind --set-api-key YOUR_API_KEY"
    echo
    print_warning "首次使用需要设置VirusTotal API密钥！"
    echo "获取API密钥: https://www.virustotal.com/gui/join-us"
}

# 主安装函数
main() {
    echo
    print_info "开始安装 IPFind..."
    echo
    
    # 检查当前目录
    if [ ! -f "ipfind_app.py" ]; then
        print_error "请在IPFind目录中运行此脚本"
        exit 1
    fi
    
    # 检测系统
    detect_os
    
    # 检查Python
    if ! check_python; then
        print_error "请先安装Python3"
        exit 1
    fi
    
    # 检查系统工具
    if ! check_system_tools; then
        print_info "尝试安装缺失的工具..."
        install_dependencies
    fi
    
    # 安装Python依赖
    install_python_deps
    
    # 设置权限
    set_permissions
    
    # 创建启动器
    create_launcher
    
    # 显示使用说明
    show_usage
}

# 运行主函数
main "$@"