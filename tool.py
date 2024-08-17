#!/usr/bin/env python3
# pylint: disable=line-too-long, missing-class-docstring, missing-function-docstring
# Copyright (C) 2024 The MIO-KITCHEN-SOURCE Project
#
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.gnu.org/licenses/agpl-3.0.en.html#license-text
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ctypes
import hashlib
import json
import os
import platform
import shutil
import subprocess
import threading
from collections import deque
from functools import wraps
from random import randrange
from tkinter import (Tk, BOTH, LEFT, RIGHT, Canvas, Text, StringVar, IntVar, TOP, Toplevel,
                     HORIZONTAL, Frame, Label, Listbox, DISABLED, Menu, BooleanVar, CENTER)
from tkinter import filedialog
from tkinter.ttk import Scrollbar, Button, LabelFrame, Entry, Combobox, Checkbutton, Progressbar, Treeview
from PIL.Image import open as open_img
from PIL.ImageTk import PhotoImage
import logging
import requests
from requests import ConnectTimeout, HTTPError
import zipfile
from io import BytesIO
import sv_ttk
from dumper import Dumper
from utils import lang, gettype, hum_convert, findfile, findfolder, Sdat2img

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Утилиты
def read_json(file_path):
    """Чтение JSON файла."""
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def write_json(file_path, data):
    """Запись данных в JSON файл."""
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)

def execute_command(command):
    """Выполнение команды в командной строке."""
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Команда '{e.cmd}' завершилась с ошибкой: {e.stderr}")
        return None

def download_file(url, destination):
    """Скачивание файла по URL."""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except (ConnectTimeout, HTTPError) as e:
        logging.error(f"Ошибка при скачивании файла: {e}")
        return False
class States:
    """Класс для хранения глобальных состояний приложения."""
    update_window = False
    donate_window = False
    mpk_store = False
    open_pids = []
    run_source = True if gettype(sys.argv[0]) == "unknown" else False
    in_oobe = False

class JsonEdit:
    """Класс для работы с JSON файлами."""
    def __init__(self, json_file):
        self.file = json_file

    def read(self):
        """Чтение данных из JSON файла."""
        if not os.path.exists(self.file):
            logging.warning(f"Файл {self.file} не существует.")
            return {}
        try:
            return read_json(self.file)
        except json.JSONDecodeError as e:
            logging.error(f"Ошибка декодирования JSON из {self.file}: {e}")
            return {}

    def write(self, data):
        """Запись данных в JSON файл."""
        write_json(self.file, data)

    def edit(self, name, value):
        """Редактирование значения в JSON файле."""
        data = self.read()
        data[name] = value
        self.write(data)

class LoadAnim:
    """Класс для загрузки анимации."""
    gifs = []

    def __init__(self):
        self.frames = []
        self.hide_gif = False
        self.frame = None
        self.tasks = {}

    def run(self, ind: int = 0):
        """Запуск анимации."""
        self.hide_gif = False
        if not self.hide_gif:
            win.gif_label.pack(padx=10, pady=10)
        self.frame = self.frames[ind]
        ind += 1
        if ind == len(self.frames):
            ind = 0
        win.gif_label.configure(image=self.frame)
        self.gifs.append(win.gif_label.after(30, self.run, ind))

    def stop(self):
        """Остановка анимации."""
        for i in self.gifs:
            try:
                win.gif_label.after_cancel(i)
            except Exception:
                logging.exception('Ошибка при остановке анимации')
        win.gif_label.pack_forget()
        self.hide_gif = True

    def init(self):
        """Инициализация анимации."""
        self.run()
        self.stop()

    def load_gif(self, gif):
        """Загрузка GIF файла."""
        try:
            while True:
                self.frames.append(PhotoImage(gif))
                gif.seek(len(self.frames))
        except EOFError:
            logging.exception('Ошибка при загрузке GIF')

    def __call__(self, func):
        """Декоратор для запуска функции с анимацией."""
        @wraps(func)
        def call_func(*args, **kwargs):
            cz(self.run())
            task_num = func.__name__
            task_real = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
            info = [hash(func), args, task_real]
            if task_num in self.tasks:
                try:
                    self.tasks[task_num].index(info)
                except ValueError:
                    self.tasks[task_num].append(info)
                else:
                    print(f"Пожалуйста, подождите выполнения задачи {task_real.native_id} с аргументами {info[1]}...\n")
                    return
            else:
                self.tasks[task_num] = [info]
            task_real.start()
            task_real.join()
            if task_num in self.tasks:
                if len(self.tasks[task_num]) - 1 >= 0:
                    del self.tasks[task_num][self.tasks[task_num].index(info)]
                else:
                    del self.tasks[task_num]
                if not self.tasks[task_num]:
                    del self.tasks[task_num]
            del info, task_num
            if not self.tasks:
                self.stop()

        return call_func

animation = LoadAnim()
class ToolBox(ttk.Frame):
    """Класс для создания панели инструментов."""
    def __init__(self, master):
        super().__init__(master=master)

    def __on_mouse(self, event):
        """Обработка события прокрутки мыши."""
        self.canvas.yview_scroll(-1 * int(event.delta / 120), "units")

    def pack_basic(self):
        """Базовая настройка панели инструментов."""
        scrollbar = Scrollbar(self, orient='vertical')
        scrollbar.pack(side='right', fill='y', padx=10, pady=10)
        self.canvas = Canvas(self, yscrollcommand=scrollbar.set)
        self.canvas.pack_propagate(False)
        self.canvas.pack(fill='both', expand=True)
        scrollbar.config(command=self.canvas.yview)
        self.label_frame = Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.label_frame, anchor='nw')
        self.canvas.bind_all("<MouseWheel>",
                             lambda event: self.__on_mouse(event))

    def gui(self):
        """Создание интерфейса панели инструментов."""
        self.pack_basic()
        width = 17
        ttk.Button(self.label_frame, text=lang.text114, command=lambda: cz(download_file), width=width).grid(row=0,
                                                                                                             column=0,
                                                                                                             padx=5,
                                                                                                             pady=5)
        ttk.Button(self.label_frame, text=lang.t59, command=self.GetFileInfo, width=width).grid(row=0, column=1, padx=5,
                                                                                                pady=5)
        ttk.Button(self.label_frame, text=lang.t60, command=self.FileBytes, width=width).grid(row=0, column=2, padx=5,
                                                                                              pady=5)
        ttk.Button(self.label_frame, text=lang.audit_allow, command=self.SelinuxAuditAllow, width=width).grid(row=1,
                                                                                                              column=0,
                                                                                                              padx=5,
                                                                                                              pady=5)
        self.update_ui()

    def update_ui(self):
        """Обновление интерфейса."""
        self.label_frame.update_idletasks()
        self.canvas.config(scrollregion=self.canvas.bbox('all'), highlightthickness=0)

    class SelinuxAuditAllow(Toplevel):
        """Класс для управления разрешениями SELinux."""
        def __init__(self):
            super().__init__()
            self.title(lang.audit_allow)
            self.gui()
            jzxs(self)

        def gui(self):
            """Создание интерфейса для управления разрешениями SELinux."""
            f = Frame(self)
            self.choose_file = StringVar(value='')
            ttk.Label(f, text=lang.log_file).pack(side=LEFT, fill=X, padx=5, pady=5)
            ttk.Entry(f, textvariable=self.choose_file).pack(side=LEFT, fill=X, padx=5, pady=5)
            ttk.Button(f, text=lang.choose, command=lambda: self.choose_file.set(
                filedialog.askopenfilename(title=lang.text25, filetypes=(('Log File', "*.log"), ('Log File', "*.txt")))) == self.lift()).pack(side=LEFT,
                                                                                         fill=X, padx=5,
                                                                                         pady=5)
            f.pack(padx=5, pady=5, anchor='nw', fill=X)
            f2 = Frame(self)
            self.output_dir = StringVar(value='')
            ttk.Label(f2, text=lang.output_folder).pack(side=LEFT, fill=X, padx=5, pady=5)
            ttk.Entry(f2, textvariable=self.output_dir).pack(side=LEFT, fill=X, padx=5, pady=5)
            ttk.Button(f2, text=lang.choose,
                       command=lambda: self.output_dir.set(filedialog.askdirectory()) == self.lift()).pack(side=LEFT,
                                                                                                           fill=X,
                                                                                                           padx=5,
                                                                                                           pady=5)
            f2.pack(padx=5, pady=5, anchor='nw', fill=X)
            ttk.Label(self, text='By github@Deercall').pack()
            self.button = ttk.Button(self, text=lang.text22, command=self.run, style='Accent.TButton')
            self.button.pack(padx=5, pady=5, fill=X)

        def run(self):
            """Запуск процесса управления разрешениями SELinux."""
            if self.button.cget('text') == lang.done:
                self.destroy()
            self.button.configure(text=lang.running, state='disabled')
            cz(selinux_audit_allow, self.choose_file.get(), self.output_dir.get())
            self.button.configure(text=lang.done, state='normal', style='')

    class FileBytes(Toplevel):
        """Класс для конвертации размеров файлов."""
        def __init__(self):
            super().__init__()
            self.values = ("B", "KB", "MB", "GB", 'TB')
            self.title(lang.t60)
            self.gui()

        def gui(self):
            """Создание интерфейса для конвертации размеров файлов."""
            self.f = Frame(self)
            self.f.pack(pady=5, padx=5, fill=X)
            self.origin_size = ttk.Entry(self.f)
            self.origin_size.bind("<KeyRelease>", lambda *x: self.calc())
            self.origin_size.pack(side='left', padx=5)
            self.h = ttk.Combobox(self.f, values=self.values, state='readonly', width=3)
            self.h.current(0)
            self.h.bind("<<ComboboxSelected>>", lambda *x: self.calc())
            self.h.pack(side='left', padx=5)
            Label(self.f, text='=').pack(side='left', padx=5)
            self.result_size = ttk.Entry(self.f)
            self.result_size.pack(side='left', padx=5)
            self.f_ = ttk.Combobox(self.f, values=self.values, state='readonly', width=3)
            self.f_.current(0)
            self.f_.bind("<<ComboboxSelected>>", lambda *x: self.calc())
            self.f_.pack(side='left', padx=5)
            ttk.Button(self, text=lang.text17, command=self.destroy).pack(fill=BOTH, padx=5, pady=5)
            jzxs(self)

        def calc(self):
            """Вычисление конвертированного размера файла."""
            self.result_size.delete(0, tk.END)
            self.result_size.insert(0, self.__calc(self.h.get(), self.f_.get(), self.origin_size.get()))

        def __calc(self, origin: str, convert: str, size) -> str:
            """Конвертация размера файла из одной единицы в другую."""
            if origin == convert:
                return size
            try:
                origin_size = float(size)
            except ValueError:
                return "0"

            units = {
                "B": 1,
                "KB": 2 ** 10,
                "MB": 2 ** 20,
                "GB": 2 ** 30,
                "TB": 2 ** 30 * 1024
            }

            return str(origin_size * units[origin] / units[convert])

    class GetFileInfo(Toplevel):
        """Класс для получения информации о файле."""
        def __init__(self):
            super().__init__()
            self.title(lang.t59)
            self.controls = []
            self.gui()
            self.geometry("400x450")
            self.resizable(False, False)
            jzxs(self)

        def gui(self):
            """Создание интерфейса для получения информации о файле."""
            a = ttk.LabelFrame(self, text='Drop')
            (tl := ttk.Label(a, text=lang.text132_e)).pack(fill=BOTH, padx=5, pady=5)
            tl.bind('<Button-1>', lambda *x: self.dnd([filedialog.askopenfilename()]))
            a.pack(side=TOP, padx=5, pady=5, fill=BOTH)
            if os.name == 'nt':
                windnd.hook_dropfiles(a, self.dnd)
            self.b = ttk.LabelFrame(self, text='INFO')
            self.b.pack(fill=BOTH, side=TOP)

        def put_info(self, name, value):
            """Вывод информации о файле в интерфейс."""
            f = Frame(self.b)
            self.controls.append(f)
            ttk.Label(f, text=f"{name}:", width=7).pack(fill=X, side='left')
            f_e = ttk.Entry(f)
            f_e.insert(0, value)
            f_e.pack(fill=X, side='left', padx=5, pady=5, expand=True)
            f_b = ttk.Button(f, text=lang.scopy)
            f_b.configure(command=lambda e=f_e, b=f_b: self.copy_to_clipboard(e.get(), b))
            f_b.pack(fill=X, side='left', padx=5, pady=5)
            f.pack(fill=X)

        @staticmethod
        def copy_to_clipboard(value, b: ttk.Button):
            """Копирование значения в буфер обмена."""
            b.configure(text=lang.scopied, state='disabled')
            win.clipboard_clear()
            win.clipboard_append(value)
            b.after(1500, lambda: b.configure(text=lang.scopy, state='normal'))

        def clear(self):
            """Очистка информации о файлах."""
            for i in self.controls:
                try:
                    i.destroy()
                except:
                    logging.exception('Ошибка при очистке')

        def dnd(self, file_list: list):
            """Обработка перетаскивания файлов."""
            cz(self.__dnd, file_list)

        def __dnd(self, file_list: list):
            """Получение информации о перетаскиваемом файле."""
            self.clear()
            self.lift()
            self.focus_force()
            file = file_list[0]
            if isinstance(file, bytes):
                try:
                    file = file_list[0].decode('utf-8')
                except:
                    file = file_list[0].decode('gbk')
            if not os.path.isfile(file) or not file:
                self.put_info('Warn', 'Пожалуйста, выберите файл')
                return
            self.put_info(lang.name, os.path.basename(file))
            self.put_info(lang.path, file)
            self.put_info(lang.type, gettype(file))
            self.put_info(lang.size, hum_convert(os.path.getsize(file)))
            self.put_info(f"{lang.size}(B)", os.path.getsize(file))
            self.put_info(lang.time, time.ctime(os.path.getctime(file)))
            self.put_info("MD5", calculate_md5_file(file))
            self.put_info("SHA256", calculate_sha256_file(file))
class Tool(Tk):
    """Основной класс приложения."""
    def __init__(self):
        super().__init__()
        self.tab6 = None
        self.rotate_angle = 0
        self.title('MIO-KITCHEN')
        if os.name != "posix":
            self.iconphoto(True, PhotoImage(data=images.icon_byte))
        sys.stdout = DevNull()

    def put_log(self):
        """Запись логов в файл."""
        log_ = settings.path + os.sep + v_code() + '.txt'
        with open(log_, 'w', encoding='utf-8', newline='\n') as f:
            f.write(self.show.get(1.0, tk.END))
            self.show.delete(1.0, tk.END)
        print(lang.text95 + log_)

    def get_time(self):
        """Получение текущего времени."""
        self.tsk.config(text=time.strftime("%H:%M:%S"))
        self.after(1000, self.get_time)

    def gui(self):
        """Создание интерфейса приложения."""
        self.sub_win2 = ttk.Frame(self)
        self.sub_win3 = ttk.Frame(self)
        self.sub_win3.pack(fill=BOTH, side=LEFT, expand=True)
        self.sub_win2.pack(fill=BOTH, side=LEFT, expand=True)
        self.notepad = ttk.Notebook(self.sub_win2)
        self.tab = ttk.Frame(self.notepad)
        self.tab2 = ttk.Frame(self.notepad)
        self.tab3 = ttk.Frame(self.notepad)
        self.tab4 = ttk.Frame(self.notepad)
        self.tab5 = ttk.Frame(self.notepad)
        self.tab6 = ttk.Frame(self.notepad)
        self.tab7 = ttk.Frame(self.notepad)
        self.notepad.add(self.tab, text=lang.text11)
        self.notepad.add(self.tab2, text=lang.text12)
        self.notepad.add(self.tab7, text=lang.text19)
        self.notepad.add(self.tab3, text=lang.text13)
        self.notepad.add(self.tab4, text=lang.text14)
        self.notepad.add(self.tab5, text=lang.text15)
        self.notepad.add(self.tab6, text=lang.toolbox)
        self.notepad.pack(fill=BOTH, expand=True)

        self.rzf = ttk.Frame(self.sub_win3)
        self.tsk = Label(self.sub_win3, text="MIO-KITCHEN", font=(None, 15))
        self.tsk.pack(padx=10, pady=10, side='top')
        self.scroll = ttk.Scrollbar(self.rzf)
        self.show = Text(self.rzf)
        self.show.pack(side=LEFT, fill=BOTH, expand=True)
        sys.stdout = StdoutRedirector(self.show)
        sys.stderr = StdoutRedirector(self.show, error_=True)
        self.scroll.pack(side=LEFT, fill=BOTH)
        self.scroll.config(command=self.show.yview)
        self.show.config(yscrollcommand=self.scroll.set)
        ttk.Button(self.rzf, text=lang.text105, command=lambda: self.show.delete(1.0, tk.END)).pack(side='bottom',
                                                                                                    padx=10,
                                                                                                    pady=5,
                                                                                                    expand=True)
        ttk.Button(self.rzf, text=lang.text106, command=lambda: self.put_log()).pack(side='bottom', padx=10, pady=5,
                                                                                     expand=True)
        self.rzf.pack(padx=5, pady=5, fill=BOTH, side='bottom')
        self.gif_label = Label(self.rzf)
        self.gif_label.pack(padx=10, pady=10)

    def tab_content(self):
        """Содержимое первой вкладки."""
        pass

    def tab6_content(self):
        """Содержимое вкладки инструментов."""
        pass

    def tab4_content(self):
        """Содержимое другой вкладки."""
        pass

class DevNull:
    """Класс для подавления вывода."""
    def write(self, string):
        pass

    @staticmethod
    def flush():
        pass
def calculate_md5_file(file_path):
    """Вычисление MD5 хеша файла."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def calculate_sha256_file(file_path):
    """Вычисление SHA256 хеша файла."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Основной код
if __name__ == "__main__":
    # Инициализация приложения
    app = Tool()
    app.gui()
    app.mainloop()
