# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
from queue import Queue


class ToolDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Tool Dashboard Manager")
        self.root.geometry("650x650")
        self.root.resizable(False, False)
        
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.ui_queue = Queue()
        self.tool_buttons = {}
        
        self.setup_ui()
        self.process_queue()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Tool.TButton', font=('Segoe UI', 11), padding=(20, 15))
        style.configure('Run.TButton', font=('Segoe UI', 11), padding=(20, 15), foreground='#27ae60')
        
        # Header
        ttk.Label(self.root, text="Tool Dashboard Manager", font=('Segoe UI', 16, 'bold')).pack(pady=20)
        
        # Tools
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tools = [
            ("cai_pm", "Cai dat phan mem", "Cai dat phan mem/Cai dat phan mem.exe"),
            ("office", "Office, WinRAR, IDM", "OFFICE, WINRAR, IDM/Main.bat"),
            ("avl", "PITVN AVL Tool", "PITVN_AVLtool/AVL.cmd"),
            ("sao_luu", "Sao luu du lieu", "Sao luu du lieu/Sao luu du lieu.exe"),
            ("backup", "Backup Windows", "Backuppwin/BackupWin.exe"),
            ("winpe2", "Tao Boot WinPE", "Tao boot WinPe 2/Tao boot WinPE.exe"),
            ("bitlocker", "Tat BitLocker", "Tat Bitlocker/Tat Bitlocker.exe"),
            ("tuychon", "Tuy chinh Windows", "Tuy chinh Windows/Tuy chinh Windows.exe"),
            ("tienich", "Tien ich cai Win dao", "Tien ich cai win dao v2.1.1.4/Tien ich cai win dao v2.1.1.4.exe"),
            ("quanly", "Quan ly file/folder", "Quan ly file_folder v1.8/Quan ly file_folder v1.8.exe"),
            ("fixboot", "Fix Boot Win AIO", "FIX_BOOTWIN_AIO/PITROYTECH_BOOT_FIX_AIO_V1.0.exe"),
        ]
        
        for i, (tid, name, path) in enumerate(tools):
            btn = ttk.Button(frame, text=name, style='Tool.TButton', width=25,
                           command=lambda p=path, n=name, t=tid: self.run(t, n, p))
            btn.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="nsew")
            self.tool_buttons[tid] = btn
        
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        
        # Status
        self.status = tk.StringVar(value="San sang")
        ttk.Separator(self.root).pack(fill=tk.X, padx=10)
        bottom = ttk.Frame(self.root, padding=10)
        bottom.pack(fill=tk.X)
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Thoat", command=self.on_close).pack(side=tk.RIGHT)
    
    def run(self, tid, name, path):
        self.ui_queue.put(('status', f"Dang khoi dong {name}..."))
        self.ui_queue.put(('btn', (tid, 'Run.TButton')))
        self.executor.submit(self._exec, tid, name, path)
    
    def _exec(self, tid, name, path):
        full = os.path.join(self.base_path, path)
        try:
            if not os.path.exists(full):
                self.ui_queue.put(('error', f"Khong tim thay:\n{full}"))
                return
            
            wd = os.path.dirname(full)
            cmd = f'Start-Process "{full}" -Verb RunAs -WorkingDirectory "{wd}"'
            if full.lower().endswith(('.bat', '.cmd')):
                cmd = f'Start-Process cmd -ArgumentList \'/c, "{full}"\' -Verb RunAs -WorkingDirectory "{wd}"'
            
            subprocess.Popen(['powershell', '-Command', cmd], creationflags=0x08000000)
            self.ui_queue.put(('status', f"Da khoi dong {name}"))
        except Exception as e:
            self.ui_queue.put(('error', str(e)))
        finally:
            self.ui_queue.put(('btn', (tid, 'Tool.TButton')))
    
    def process_queue(self):
        while not self.ui_queue.empty():
            act, data = self.ui_queue.get_nowait()
            if act == 'status': self.status.set(data)
            elif act == 'error': messagebox.showerror("Loi", data)
            elif act == 'btn': self.tool_buttons[data[0]].configure(style=data[1])
        self.root.after(50, self.process_queue)
    
    def on_close(self):
        self.executor.shutdown(wait=False)
        self.root.destroy()


if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    
    root = tk.Tk()
    ToolDashboard(root)
    root.mainloop()
