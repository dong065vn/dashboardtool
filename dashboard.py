"""
Dashboard Tool Manager - Tích hợp tất cả các tool vào một giao diện duy nhất
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import sys

class ToolDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("🛠️ Tool Dashboard Manager")
        self.root.geometry("600x500")
        self.root.resizable(False, False)
        
        # Lấy đường dẫn thư mục hiện tại
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        
        # Cấu hình style
        self.setup_style()
        
        # Tạo giao diện
        self.create_header()
        self.create_tool_buttons()
        self.create_status_bar()
    
    def setup_style(self):
        """Cấu hình style cho giao diện"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Style cho button
        style.configure('Tool.TButton', 
                       font=('Segoe UI', 11), 
                       padding=(20, 15))
        
        # Style cho header
        style.configure('Header.TLabel', 
                       font=('Segoe UI', 16, 'bold'),
                       foreground='#2c3e50')
    
    def create_header(self):
        """Tạo header"""
        header_frame = ttk.Frame(self.root, padding="20 20 20 10")
        header_frame.pack(fill=tk.X)
        
        title = ttk.Label(header_frame, 
                         text="🖥️ Tool Dashboard Manager",
                         style='Header.TLabel')
        title.pack()
        
        subtitle = ttk.Label(header_frame, 
                            text="Click vào nút để khởi động tool tương ứng",
                            font=('Segoe UI', 10))
        subtitle.pack(pady=(5, 0))
    
    def create_tool_buttons(self):
        """Tạo các nút tool"""
        # Frame chứa các nút
        button_frame = ttk.Frame(self.root, padding="20")
        button_frame.pack(fill=tk.BOTH, expand=True)
        
        # Danh sách các tool
        tools = [
            {
                "name": "📦 Office, WinRAR, IDM",
                "path": "OFFICE, WINRAR, IDM/Main.bat",
                "desc": "Cài đặt Office, WinRAR và IDM"
            },
            {
                "name": "🔧 PITVN AVL Tool",
                "path": "PITVN_AVLtool/AVL.cmd",
                "desc": "Công cụ AVL từ PITVN"
            },
            {
                "name": "💾 Sao lưu dữ liệu",
                "path": "Sao luu du lieu/Sao luu du lieu.exe",
                "desc": "Sao lưu dữ liệu quan trọng"
            },
            {
                "name": "🚀 Tạo Boot WinPE",
                "path": "Tao boot WinPe 2/Tao boot WinPE.exe",
                "desc": "Tạo USB boot WinPE"
            },
            {
                "name": "🔓 Tắt BitLocker",
                "path": "Tat Bitlocker/Tat Bitlocker.exe",
                "desc": "Vô hiệu hóa BitLocker"
            },
            {
                "name": "⚙️ Tùy chỉnh Windows",
                "path": "Tuy chinh Windows/Tuy chinh Windows.exe",
                "desc": "Tùy chỉnh cài đặt Windows"
            }
        ]
        
        # Tạo grid 2 cột
        for i, tool in enumerate(tools):
            row = i // 2
            col = i % 2
            
            # Frame cho mỗi tool
            tool_frame = ttk.Frame(button_frame, padding="5")
            tool_frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            
            # Nút bấm
            btn = ttk.Button(tool_frame, 
                           text=tool["name"],
                           style='Tool.TButton',
                           command=lambda p=tool["path"], n=tool["name"]: self.run_tool(p, n),
                           width=25)
            btn.pack(fill=tk.X)
            
            # Mô tả
            desc_label = ttk.Label(tool_frame, 
                                  text=tool["desc"],
                                  font=('Segoe UI', 9),
                                  foreground='#7f8c8d')
            desc_label.pack(pady=(3, 0))
        
        # Cấu hình grid
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
    
    def create_status_bar(self):
        """Tạo thanh trạng thái"""
        self.status_var = tk.StringVar(value="Sẵn sàng")
        
        status_frame = ttk.Frame(self.root, padding="10")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Separator(status_frame, orient='horizontal').pack(fill=tk.X, pady=(0, 10))
        
        status_label = ttk.Label(status_frame, 
                                textvariable=self.status_var,
                                font=('Segoe UI', 9))
        status_label.pack(side=tk.LEFT)
        
        # Nút thoát
        exit_btn = ttk.Button(status_frame, 
                             text="❌ Thoát",
                             command=self.root.quit)
        exit_btn.pack(side=tk.RIGHT)
    
    def run_tool(self, relative_path, tool_name):
        """Chạy tool được chọn"""
        full_path = os.path.join(self.base_path, relative_path)
        
        # Kiểm tra file tồn tại
        if not os.path.exists(full_path):
            messagebox.showerror("Lỗi", f"Không tìm thấy file:\n{full_path}")
            self.status_var.set(f"❌ Lỗi: Không tìm thấy {tool_name}")
            return
        
        try:
            self.status_var.set(f"🔄 Đang khởi động {tool_name}...")
            self.root.update()
            
            # Lấy thư mục chứa file
            working_dir = os.path.dirname(full_path)
            
            # Chạy file dựa vào loại
            if full_path.endswith('.bat') or full_path.endswith('.cmd'):
                subprocess.Popen(['cmd', '/c', full_path], 
                               cwd=working_dir,
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
            elif full_path.endswith('.exe'):
                subprocess.Popen([full_path], 
                               cwd=working_dir,
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
            
            self.status_var.set(f"✅ Đã khởi động {tool_name}")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể chạy tool:\n{str(e)}")
            self.status_var.set(f"❌ Lỗi khi chạy {tool_name}")


def main():
    root = tk.Tk()
    
    # Icon cho cửa sổ (nếu có)
    try:
        root.iconbitmap(default='')
    except:
        pass
    
    app = ToolDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
