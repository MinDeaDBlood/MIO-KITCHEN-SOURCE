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
import os
import logging
from difflib import SequenceMatcher
from tkinter import Toplevel, ttk, BOTH
from typing import Optional, Dict
from .utils import move_center, prog_path, lang
import polib  # Библиотека для работы с .po файлами
import json

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Функция для определения языка по умолчанию
def detect_language() -> str:
    """
    Определяет язык системы из переменной окружения LANG или LANGUAGE.
    
    :return: Код языка (например, 'en', 'ru').
    """
    lang_env = os.getenv('LANG', 'en').split('.')[0]  # Пример: 'ru_RU.UTF-8' -> 'ru_RU'
    language_code = lang_env.split('_')[0]  # Пример: 'ru_RU' -> 'ru'
    logging.info(f"Detected system language: {language_code}")
    return language_code

# Загрузка переводов из .po файла
def load_translations(language: str = 'en') -> Dict[str, str]:
    """
    Загружает переводы из .po файла для указанного языка.
    
    :param language: Код языка (например, 'en', 'ru').
    :return: Словарь переводов {оригинальное сообщение: перевод}.
    """
    po_path = os.path.join(prog_path, 'locales', language, 'LC_MESSAGES', 'ai_engine.po')
    translations = {}
    try:
        po = polib.pofile(po_path)
        for entry in po:
            translations[entry.msgid] = entry.msgstr
    except FileNotFoundError:
        logging.warning(f"Файл перевода не найден: {po_path}")
    except Exception as e:
        logging.error(f"Ошибка при загрузке .po файла: {e}")
    return translations

# Получение перевода
def translate(message: str, translations: Dict[str, str]) -> str:
    """
    Возвращает перевод для указанного сообщения.
    
    :param message: Оригинальное сообщение.
    :param translations: Словарь переводов.
    :return: Переведенное сообщение или оригинальное сообщение, если перевода нет.
    """
    return translations.get(message, message)

# Основная функция
def suggest(string: str = '', language: Optional[str] = None, ok: str = 'OK', allow_multiple_windows: bool = False) -> Optional[None]:
    """
    Отображает окно с подсказками на основе строки ошибок.
    
    :param string: Строка, содержащая текст ошибки.
    :param language: Код языка (например, 'en', 'ru'). Если None, используется язык системы.
    :param ok: Текст кнопки для закрытия окна.
    :param allow_multiple_windows: Разрешить создание нескольких окон одновременно.
    """
    if not string:
        logging.warning("Переданная строка пуста.")
        return

    # Определение языка по умолчанию
    language = language or detect_language()

    # Загрузка переводов
    translations = load_translations(language)

    # Поиск ошибок в строке
    catch_error = next((i for i in string.split("\n") if 'error' in i or 'failed' in i), None)
    if not catch_error:
        logging.info(translate("No errors found in the string.", translations))
        return

    # Предотвращение дублирования окон
    if not allow_multiple_windows and hasattr(suggest, '_active_window'):
        logging.info(translate("A window is already active. Creating a new window is canceled.", translations))
        return

    similarity = 0
    window = Toplevel()
    suggest._active_window = window  # Отслеживание активного окна
    window.protocol("WM_DELETE_WINDOW", lambda: setattr(suggest, '_active_window', None))
    window.resizable(False, False)
    window.title(translate("AI ENGINE", translations))

    # Значения по умолчанию
    text = translate("No idea about:\n\t%s\nPlease Report It To us.", translations) % string
    detail = translate("Unknown", translations)

    # Поиск в библиотеке
    help_document_path = os.path.join(prog_path, 'bin', 'help_document.json')
    library = load_library(help_document_path)
    for i, item in library.items():
        current_language = item.get(language, 'English')
        detail = item.get('detail', {}).get(language, translate("Unknown", translations))

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

# Загрузка библиотеки (JSON-файл)
def load_library(path: str) -> Dict:
    """Загружает библиотеку данных из указанного файла JSON."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("File not found: %s" % path)
    except ValueError:
        logging.error("Error parsing JSON file: %s" % path)
    return {}
