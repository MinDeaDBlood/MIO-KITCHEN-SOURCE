# src/core/merge_sparse.py 

import os
import re
import logging
from typing import List, Optional, Generator, Tuple


# --- ИЗМЕНЕНИЕ 2: Создаем именованный логгер для этого модуля ---
logger = logging.getLogger(__name__)

def natural_sort_key(s: str) -> List: return [int(text) if text.isdigit() else text.lower() for text in re.split('([0-9]+)', s)]
def find_simg2img_executable(settings) -> Optional[str]:
    tool_bin_path = getattr(settings, 'tool_bin', '')
    if not tool_bin_path or not os.path.isdir(tool_bin_path): logging.error("..."); return None
    for name in ('simg2img.exe', 'simg2img'):
        if os.path.exists(os.path.join(tool_bin_path, name)): return name
    logging.error("..."); return None
def _find_and_sort_segments(project_path: str) -> List[str]:
    segment_pattern = re.compile(r'.*(_sparsechunk|sparse_chunk|\.chunk|\.img)\.\d+$')
    all_files = os.listdir(project_path)
    segment_files = [f for f in all_files if segment_pattern.match(f) and os.path.isfile(os.path.join(project_path, f))]
    segment_files.sort(key=natural_sort_key)
    return [os.path.join(project_path, f) for f in segment_files]
def _delete_source_segments(segment_paths: List[str], lang):
    logging.info(f"> {getattr(lang, 'deleting_source_segments_msg', 'Deleting source segments...')}")
    for segment_file in segment_paths:
        try:
            os.remove(segment_file)
            logging.info(f"  - {getattr(lang, 'deleted_file_msg', 'Deleted: {filename}').format(filename=os.path.basename(segment_file))}")
        except OSError as e:
            logging.error(f"  - {getattr(lang, 'delete_error_msg', 'Failed to delete {filename}: {error}').format(filename=os.path.basename(segment_file), error=e)}")

def smart_merge_generator(
    project_path: str, output_name: str, utils
) -> Generator[Tuple[int, Optional[str]], None, Optional[str]]:
    lang = utils.lang
    output_path = os.path.join(project_path, output_name)
    
    executable_name = find_simg2img_executable(utils.settings)
    if not executable_name:
        utils.warn_win(getattr(lang, 'simg2img_not_found_error', 'simg2img not found.'))
        return None

    segment_file_paths = _find_and_sort_segments(project_path)
    if not segment_file_paths:
        logging.info(f"> {getattr(lang, 't_no_file_segments_found', 'No segments found.')}")
        return # Просто завершаем генератор

    logging.info(f"> {getattr(lang, 'segments_found_msg', 'Found segments:')}")
    for f in segment_file_paths:
        logging.info(f"  - {os.path.basename(f)}")

    total_size = sum(os.path.getsize(p) for p in segment_file_paths)
    if total_size == 0:
        logging.warning("Total size of segments is 0. Nothing to merge.")
        return
        
    processed_size = 0
    
    first_segment = segment_file_paths[0]
    command = [executable_name, first_segment, output_path]
    logging.info(f"\n> {getattr(lang, 'running_command_msg', 'Running command:').format(command=' '.join(command))}")
    logging.info(f"> {getattr(lang, 'processing_segment', 'Processing: {filename}').format(filename=os.path.basename(first_segment))}")
    return_code = utils.call(command, out=False)
    
    if return_code != 0:
        utils.warn_win(getattr(lang, 'merge_fail_initial', 'Initial merge failed for {filename}').format(filename=os.path.basename(first_segment)))
        if os.path.exists(output_path): os.remove(output_path)
        return None
        
    processed_size += os.path.getsize(first_segment)
    yield (int(processed_size * 100 / total_size), output_path)

    try:
        with open(output_path, "ab") as f_out:
            for segment_path in segment_file_paths[1:]:
                logging.info(f"> {getattr(lang, 'appending_segment', 'Appending: {filename}').format(filename=os.path.basename(segment_path))}")
                with open(segment_path, "rb") as f_in:
                    f_out.write(f_in.read())
                
                processed_size += os.path.getsize(segment_path)
                yield (int(processed_size * 100 / total_size), output_path)
    except IOError as e:
        utils.warn_win(getattr(lang, 'merge_fail_append', 'Append failed: {error}').format(error=e))
        if os.path.exists(output_path): os.remove(output_path)
        return None

    return output_path

def main(project_path: str, output_name: str = "super.img", delete_source: bool = False, progress_callback=None, utils=None):
    if not utils:
        from . import utils as local_utils
        utils = local_utils

    lang = utils.lang
    output_path = os.path.join(project_path, output_name)

    if not os.path.isdir(project_path):
        utils.warn_win(getattr(lang, 'project_path_error', 'Project path error...').format(project_path=project_path))
        return

    if os.path.exists(output_path):
        logging.info(f"> {getattr(lang, 'merge_skipped_exists', 'Output exists...').format(output_name=output_name)}")
        if progress_callback: progress_callback(100)
        return
    
    logging.info(f"> {getattr(lang, 'searching_for_segments_msg', 'Searching...').format(project_path=project_path)}")
        
    try:
        final_output = None
        for percentage, path in smart_merge_generator(project_path, output_name, utils):
            if progress_callback:
                progress_callback(percentage)
            final_output = path
        
        # --- ИСПРАВЛЕННАЯ ЛОГИКА ---
        # Мы проверяем final_output. Если он не None, значит, генератор что-то вернул.
        # Если он None, значит была ошибка, о которой уже сообщили через utils.warn_win.
        if final_output:
            if os.path.exists(final_output):
                if progress_callback: progress_callback(100)
                success_msg = getattr(lang, 'merge_success_msg', 'Merge successful...').format(output_path=final_output)
                logging.info(f"> {success_msg}")
                utils.info_win(success_msg)

                if delete_source:
                    source_segments = _find_and_sort_segments(project_path)
                    _delete_source_segments(source_segments, lang)
            # Если final_output не None, но файла нет - это была ошибка, о которой уже сообщили
            # Ничего дополнительно делать не нужно.
        
    except Exception as e:
        logging.exception("Непредвиденная ошибка в merge_sparse.main")
        error_msg = getattr(lang, 'unexpected_merge_error', 'Unexpected error: {error}').format(error=e)
        utils.warn_win(error_msg)
        if progress_callback: progress_callback(-1)