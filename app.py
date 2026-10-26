"""运行 python app.py 打开 S-AES 实验界面，仅依赖 Python 标准库。"""
import json
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import saes


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('S-AES')
        self.geometry('1100x860')
        self.minsize(900, 700)
        self.configure(background='#F4F6FA')
        self.configure_styles()
        self.events = queue.Queue()
        self.stop_attack = threading.Event()
        self.attack_running = False
        self.last_candidates = []
        header = ttk.Frame(self, style='Shell.TFrame', padding=(30, 23, 30, 18))
        header.pack(fill='x')
        ttk.Label(header, text='S-AES', style='Title.TLabel').pack(anchor='w')
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=30, pady=(0, 12))
        self.build_blocks(self.tab(notebook, '基本 / 多重加密'))
        self.build_text(self.tab(notebook, 'ASCII 字符串'))
        self.build_attack(self.tab(notebook, '中间相遇攻击'))
        self.build_cbc(self.tab(notebook, 'CBC / 篡改实验'))
        self.bind('<MouseWheel>', self.scroll_page)
        self.after(100, self.poll_events)

    def configure_styles(self):
        """使用可跨平台定制的 clam 主题，统一控件配色与状态。"""
        style = ttk.Style(self)
        style.theme_use('clam')
        self.option_add('*Font', ('Microsoft YaHei UI', 10))
        self.option_add('*TCombobox*Listbox.font', ('Microsoft YaHei UI', 10))
        style.configure('.', font=('Microsoft YaHei UI', 10), background='#FFFFFF', foreground='#263247')
        style.configure('Shell.TFrame', background='#F4F6FA')
        style.configure('Title.TLabel', background='#F4F6FA', foreground='#18243B', font=('Microsoft YaHei UI', 22, 'bold'))
        style.configure('Subtitle.TLabel', background='#F4F6FA', foreground='#738096')
        style.configure('Footer.TLabel', background='#F4F6FA', foreground='#8A94A5', font=('Microsoft YaHei UI', 9))
        style.configure('Field.TLabel', foreground='#526077', font=('Microsoft YaHei UI', 10))
        style.configure('Section.TLabel', foreground='#25334D', font=('Microsoft YaHei UI', 14, 'bold'))
        style.configure('Hint.TLabel', foreground='#7D889A', font=('Microsoft YaHei UI', 9))
        style.configure('TNotebook', background='#F4F6FA', borderwidth=0, tabmargins=(0, 0, 0, 10))
        style.configure('TNotebook.Tab', padding=(22, 12), background='#EAEFF6', foreground='#66738A', borderwidth=0, expand=(0, 0, 0, 0))
        # 覆盖主题自带的选中态 padding/expand，避免切换时标签收缩或抬升。
        style.map('TNotebook.Tab', padding=[('selected', (22, 12)), ('!selected', (22, 12))],
                  expand=[('selected', (0, 0, 0, 0)), ('!selected', (0, 0, 0, 0))],
                  background=[('selected', '#DCE6FF'), ('active', '#E2E9F4')],
                  foreground=[('selected', '#2854C5')])
        style.configure('TEntry', padding=(12, 9), fieldbackground='#F8FAFD', bordercolor='#E0E6EF', lightcolor='#E0E6EF', darkcolor='#E0E6EF')
        style.map('TEntry', bordercolor=[('focus', '#6288E8')], lightcolor=[('focus', '#6288E8')], darkcolor=[('focus', '#6288E8')])
        style.configure('TCombobox', padding=(12, 8), fieldbackground='#F8FAFD', bordercolor='#E0E6EF', arrowsize=13)
        style.map('TCombobox', fieldbackground=[('readonly', '#F8FAFD')], selectbackground=[('readonly', '#F8FAFD')], selectforeground=[('readonly', '#263247')])
        style.configure('TButton', padding=(15, 9), background='#F0F3F9', foreground='#47566F', borderwidth=0)
        style.map('TButton', background=[('pressed', '#DCE4F2'), ('active', '#E4EBF7')])
        style.configure('Primary.TButton', background='#4169DE', foreground='#FFFFFF')
        style.map('Primary.TButton', background=[('pressed', '#2E50B8'), ('active', '#345DD0')], foreground=[('disabled', '#CCD6F1')])
        style.configure('Horizontal.TProgressbar', background='#5279E2', troughcolor='#EDF1F8', borderwidth=0, thickness=6)

    def tab(self, notebook, title):
        page = ttk.Frame(notebook)
        notebook.add(page, text=title)
        canvas = tk.Canvas(page, background='#FFFFFF', highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(page, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        frame = ttk.Frame(canvas, padding=(24, 20))
        frame.scroll_canvas = canvas
        window = canvas.create_window((0, 0), window=frame, anchor='nw')

        def resize(_event=None):
            canvas.itemconfigure(window, width=canvas.winfo_width(), height=max(canvas.winfo_height(), frame.winfo_reqheight()))
            canvas.configure(scrollregion=canvas.bbox('all'))
        canvas.bind('<Configure>', resize)
        frame.bind('<Configure>', resize)
        ttk.Label(frame, text=title.replace(' / ', ' · '), style='Section.TLabel').pack(anchor='w', pady=(0, 12))
        return frame

    def scroll_page(self, event):
        widget = event.widget
        # 多行文本保留自身滚动；其他控件所在页面随鼠标滚轮滚动。
        if isinstance(widget, tk.Text):
            return
        while widget is not None:
            if hasattr(widget, 'scroll_canvas'):
                canvas = widget.scroll_canvas
                if canvas.bbox('all')[3] > canvas.winfo_height():
                    canvas.yview_scroll(-int(event.delta / 120), 'units')
                return
            widget = getattr(widget, 'master', None)

    def entry(self, parent, label, default=''):
        ttk.Label(parent, text=label, style='Field.TLabel').pack(anchor='w', pady=(10, 5))
        value = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=value, font=('Consolas', 11)).pack(fill='x')
        return value

    def output(self, parent, height=10):
        container = ttk.Frame(parent)
        container.pack(fill='both', expand=True, pady=(6, 0))
        heading = ttk.Frame(container)
        heading.pack(fill='x', pady=(0, 7))
        ttk.Label(heading, text='运行结果', style='Field.TLabel').pack(side='left')
        body = ttk.Frame(container)
        body.pack(fill='both', expand=True)
        widget = tk.Text(body, height=min(height, 6), wrap='word', font=('Consolas', 11),
                         background='#F5F7FB', foreground='#30415F', relief='flat',
                         borderwidth=0, highlightthickness=1, highlightbackground='#E7ECF3',
                         highlightcolor='#6288E8', padx=14, pady=12, spacing1=3, spacing3=4,
                         selectbackground='#DCE6FF', insertbackground='#4169DE')
        scrollbar = ttk.Scrollbar(body, orient='vertical', command=widget.yview)
        widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        widget.pack(side='left', fill='both', expand=True)
        widget.insert('1.0', '等待运行，结果将在这里显示。')
        widget.configure(state='disabled')
        ttk.Button(heading, text='复制结果', command=lambda: self.copy_result(widget)).pack(side='right')
        parent.result_container = container
        return widget

    def copy_result(self, widget):
        self.clipboard_clear()
        self.clipboard_append(widget.get('1.0', 'end-1c'))

    def show(self, widget, text):
        readonly = str(widget.cget('state')) == 'disabled'
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        if readonly:
            widget.configure(state='disabled')

    def safe(self, callback):
        def wrapped():
            try:
                callback()
            except (ValueError, UnicodeError, OSError) as error:
                messagebox.showerror('输入错误', str(error))
        return wrapped

    def buttons(self, parent, actions):
        row = ttk.Frame(parent)
        row.pack(fill='x', pady=(16, 12), before=parent.result_container)
        for label, callback in actions:
            primary = label in ('加密', '加密字符串', '开始完整攻击', 'CBC 加密')
            ttk.Button(row, text=label, style='Primary.TButton' if primary else 'TButton', command=self.safe(callback)).pack(side='left', padx=(0, 8))

    def build_blocks(self, frame):
        ttk.Label(frame, text='输入均为二进制；多重密钥从左到右为 K1、K2、K3。').pack(anchor='w')
        mode = tk.StringVar(value='单重 16-bit')
        ttk.Combobox(frame, textvariable=mode, values=['单重 16-bit', '双重 32-bit EE', '三重 48-bit EEE'], state='readonly').pack(fill='x', pady=8)
        data = self.entry(frame, '明文 / 密文（16 bit）', '1101011100101000')
        key = self.entry(frame, '密钥（根据模式输入 16 / 32 / 48 bit）', '0100101011110101')
        default_keys = {
            '单重 16-bit': f'{0x4AF5:016b}',
            '双重 32-bit EE': f'{0x1234ABCD:032b}',
            '三重 48-bit EEE': f'{0x1234ABCD5678:048b}',
        }
        mode.trace_add('write', lambda *_: key.set(default_keys[mode.get()]))
        result = self.output(frame)

        def run(decrypt):
            count = {'单重 16-bit': 1, '双重 32-bit EE': 2, '三重 48-bit EEE': 3}[mode.get()]
            block, secret = saes.parse_bits(data.get()), saes.parse_bits(key.get(), 16 * count)
            if count == 1:
                value = (saes.decrypt_block if decrypt else saes.encrypt_block)(block, secret)
            else:
                value = (saes.multiple_decrypt if decrypt else saes.multiple_encrypt)(block, secret, count)
            self.show(result, f'结果（二进制）: {value:016b}\n结果（十六进制）: {value:04X}')
        self.buttons(frame, [('加密', lambda: run(False)), ('解密', lambda: run(True)), ('载入标准向量', lambda: (mode.set('单重 16-bit'), data.set('1101011100101000'), key.set('0100101011110101')))])

    def build_text(self, frame):
        key = self.entry(frame, '16-bit 二进制密钥', '0100101011110101')
        plain = self.entry(frame, 'ASCII 明文', 'Hello S-AES!')
        cipher = self.entry(frame, '密文 HEX')
        result = self.output(frame)

        def encrypt():
            value = saes.transform_bytes(plain.get().encode('ascii'), saes.parse_bits(key.get()))
            cipher.set(value.hex().upper())
            self.show(result, 'HEX: ' + value.hex().upper() + '\n\n密文字符:\n' + json.dumps(value.decode('latin1'), ensure_ascii=True))

        def decrypt():
            value = saes.transform_bytes(bytes.fromhex(cipher.get()), saes.parse_bits(key.get()), True)
            self.show(result, '解密 ASCII: ' + value.decode('ascii'))
        self.buttons(frame, [('加密字符串', encrypt), ('解密 HEX', decrypt)])

    def build_attack(self, frame):
        ttk.Label(frame, text='每行：16-bit 明文 + 空格 + 16-bit 双重加密密文。支持多组；单组通常有多个候选。').pack(anchor='w')
        pairs = tk.Text(frame, height=5, font=('Consolas', 11), background='#F8FAFD', foreground='#30415F', relief='flat', highlightthickness=1, highlightbackground='#E0E6EF', highlightcolor='#6288E8', padx=12, pady=10, selectbackground='#DCE6FF')
        pairs.pack(fill='x', pady=10)
        status = tk.StringVar(value='尚未开始：完整搜索 K1、K2 各 65536 个值')
        ttk.Label(frame, textvariable=status).pack(anchor='w')
        progress = ttk.Progressbar(frame, maximum=131072)
        progress.pack(fill='x', pady=8)
        result = self.output(frame)
        self.attack_widgets = (status, progress, result)

        def example():
            secret = 0x1234ABCD
            self.show(pairs, '\n'.join(f'{plain:016b} {saes.multiple_encrypt(plain, secret):016b}' for plain in (0x1234, 0x5678, 0x9ABC)))

        def start():
            if self.attack_running:
                raise ValueError('攻击正在运行，请等待或取消')
            parsed = []
            for line in pairs.get('1.0', 'end').splitlines():
                if line.strip():
                    parts = line.split()
                    if len(parts) != 2:
                        raise ValueError('每行应恰好包含两项 16-bit 二进制数据')
                    parsed.append(tuple(saes.parse_bits(part) for part in parts))
            if not parsed:
                raise ValueError('请输入至少一组明密文')
            self.attack_running = True
            self.stop_attack.clear()
            status.set('正在搜索……')

            def worker():
                started = time.perf_counter()
                try:
                    candidates = saes.meet_in_the_middle(parsed, lambda done, total: self.events.put(('progress', done)), self.stop_attack.is_set)
                    self.events.put(('done', candidates, time.perf_counter() - started))
                except Exception as error:
                    self.events.put(('error', str(error)))
            threading.Thread(target=worker, daemon=True).start()

        def export():
            filename = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('文本', '*.txt')])
            if filename:
                with open(filename, 'w', encoding='utf-8') as handle:
                    handle.write('\n'.join(f'{key:032b} {key:08X}' for key in self.last_candidates))
        self.buttons(frame, [('载入三组示例', example), ('开始完整攻击', start), ('取消', self.stop_attack.set), ('导出全部候选', export)])
        example()

    def poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                status, progress, result = self.attack_widgets
                if event[0] == 'progress':
                    progress['value'] = event[1]
                    status.set(f'搜索进度 {event[1] / 131072:.1%}')
                elif event[0] == 'done':
                    self.attack_running = False
                    self.last_candidates = event[1]
                    status.set(f'完成：{len(event[1])} 个候选，用时 {event[2]:.2f} 秒')
                    self.show(result, '\n'.join(f'{key:032b}  HEX={key:08X}' for key in event[1][:200]) + ('\n仅显示前 200 个；可导出全部。' if len(event[1]) > 200 else ''))
                else:
                    self.attack_running = False
                    status.set(event[1])
        except queue.Empty:
            pass
        self.after(100, self.poll_events)

    def build_cbc(self, frame):
        key = self.entry(frame, '16-bit 二进制密钥', '0100101011110101')
        iv = self.entry(frame, '共享 IV（16 bit；加密前可生成随机 IV）', f'{saes.new_iv():016b}')
        plain = self.entry(frame, 'ASCII 明文', 'Hello CBC mode!')
        cipher = self.entry(frame, '原始密文 HEX（可复制并分享，IV 需单独共享）')
        modified = self.entry(frame, '篡改后密文 HEX（可直接编辑，实现替换或修改）')
        result = self.output(frame, height=8)

        def encrypt():
            value = saes.cbc_encrypt(plain.get().encode('ascii'), saes.parse_bits(key.get()), saes.parse_bits(iv.get()))
            cipher.set(value.hex().upper())
            modified.set(value.hex().upper())
            self.show(result, f'IV: {iv.get()}\n密文: {cipher.get()}')

        def flip():
            value = bytearray(bytes.fromhex(cipher.get()))
            if not value or len(value) % 2:
                raise ValueError('请先生成有效密文')
            value[0] ^= 1
            modified.set(value.hex().upper())

        def compare():
            secret, vector = saes.parse_bits(key.get()), saes.parse_bits(iv.get())
            original = saes.cbc_decrypt(bytes.fromhex(cipher.get()), secret, vector, False)
            changed = saes.cbc_decrypt(bytes.fromhex(modified.get()), secret, vector, False)
            lines = ['以下展示包含填充的原始字节，避免篡改填充掩盖实验结果：']
            for index in range(max(len(original), len(changed)) // 2):
                before, after = original[index*2:index*2+2], changed[index*2:index*2+2]
                lines.append(f'P{index+1}: {before.hex().upper():4} → {after.hex().upper():4}  {"相同" if before == after else "变化"}  {before!r} → {after!r}')
            lines.append('规律：修改 Ci 使 Pi 扰乱，Pi+1 在相应位翻转，后续分组恢复；CBC 不提供完整性校验。')
            self.show(result, '\n'.join(lines))

        def decrypt():
            value = saes.cbc_decrypt(bytes.fromhex(cipher.get()), saes.parse_bits(key.get()), saes.parse_bits(iv.get()))
            self.show(
                result,
                '解密 HEX: ' + value.hex().upper()
                + '\n解密字节: ' + repr(value)
                + '\n文本（不可解码字节显示为�）: '
                + value.decode('ascii', errors='replace')
            )
        self.buttons(frame, [('随机 IV', lambda: iv.set(f'{saes.new_iv():016b}')), ('CBC 加密', encrypt), ('CBC 解密', decrypt), ('翻转 C1 一位', flip), ('对比篡改结果', compare)])


if __name__ == '__main__':
    Application().mainloop()
