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
import os.path
import logging
from difflib import SequenceMatcher
from tkinter import Toplevel, ttk, BOTH
from typing import Optional, Dict
from .utils import move_center, prog_path, lang
from json import load
import gettext

# Настройка локализации
locales_dir = os.path.join(prog_path, 'locales')  # Директория с переводами
language = os.getenv('LANGUAGE', 'en')  # Язык по умолчанию
gettext.bindtextdomain('ai_engine', locales_dir)
gettext.textdomain('ai_engine')
_ = gettext.gettext  # Функция перевода

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("ai_engine.log"), logging.StreamHandler()]
)

def load_library(path: str) -> Dict:
    """Загружает библиотеку данных из указанного файла JSON."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return load(f)
    except FileNotFoundError:
        logging.error(_("File not found: %s") % path)
    except ValueError:
        logging.error(_("Error parsing JSON file: %s") % path)
    return {}

# Загрузка библиотеки
help_document_path = os.path.join(prog_path, 'bin', 'help_document.json')
library = load_library(help_document_path)

def suggest(string: str = '', language: str = 'English', ok: str = _('OK'), allow_multiple_windows: bool = False) -> Optional[None]:
    """
    Отображает окно с подсказками на основе строки ошибок.

    :param string: Строка, содержащая текст ошибки.
    :param language: Язык для отображения подсказки.
    :param ok: Текст кнопки для закрытия окна.
    :param allow_multiple_windows: Разрешить создание нескольких окон одновременно.
    """
    if not string:
        logging.warning(_("The provided string is empty."))
        return

    # Поиск ошибок в строке
    catch_error = next((i for i in string.split("\n") if 'error' in i or 'failed' in i), None)
    if not catch_error:
        logging.info(_("No errors found in the string."))
        return

    # Предотвращение дублирования окон
    if not allow_multiple_windows and hasattr(suggest, '_active_window'):
        logging.info(_("A window is already active. Creating a new window is canceled."))
        return

    similarity = 0
    window = Toplevel()
    suggest._active_window = window  # Отслеживание активного окна
    window.protocol("WM_DELETE_WINDOW", lambda: setattr(suggest, '_active_window', None))
    window.resizable(False, False)
    window.title(_("AI ENGINE"))

    # Значения по умолчанию
    text = _("No idea about:\n\t%s\nPlease Report It To us.") % string
    detail = _('Unknown')

    # Поиск в библиотеке
    for i, item in library.items():
        current_language = item.get(language, 'English')
        detail = item.get('detail', {}).get(language, _('Unknown'))

        similarity_ = SequenceMatcher(None, i, catch_error).quick_ratio()
        if similarity_ >= 0.8:
            text = item.get(language, text)
            break
        elif similarity_ > similarity:
            similarity = similarity_
            if similarity < 0.5:
                break
            text = item.get(language, text)

    # Создание окна с деталями
    f1 = ttk.LabelFrame(window, text=lang.detail)
    ttk.Label(f1, text=string, font=(None, 12), foreground="orange", wraplength=400).pack(padx=10, pady=5)
    ttk.Label(f1, text=detail, font=(None, 15), foreground="grey", wraplength=400).pack(padx=10, pady=10)
    f1.pack(padx=10, pady=10)

    f2 = ttk.LabelFrame(window, text=lang.solution)
    ttk.Label(f2, text=text, font=(None, 15), foreground="green", wraplength=400).pack(padx=10, pady=10)
    f2.pack(padx=10, pady=10)

    ttk.Button(window, text=ok, command=window.destroy, style="Accent.TButton").pack(padx=10, pady=10, fill=BOTH)
    move_center(window)
