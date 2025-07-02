#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
# Copyright (C) 2022-2025 The MIO-KITCHEN-SOURCE Project
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

import re
import sys
import json
from pathlib import Path
from typing import Dict, Generator, List, Tuple, Optional

from .utils import JsonEdit


def scan_context(context_file_path: Path) -> Dict[str, str]:
    contexts = {}
    print(f"ContextPatcher: Reading original contexts from {context_file_path.name}...")
    try:
        with context_file_path.open("r", encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    print(f"[Warning] Malformed line {line_num}: '{line}'. Skipping.")
                    continue

                path, context = parts[0], parts[1]
                path = path.replace(r'\@', '@')

                if len(parts) > 2:
                    print(f"[Warning] Line {line_num} has extra data: '{line}'. Using first two parts.")

                contexts[path] = context
    except FileNotFoundError:
        print(f"[Warning] Context file not found: {context_file_path}. Proceeding with an empty context map.")
    return contexts


def scan_dir(unpacked_dir: Path) -> Generator[str, None, None]:
    yield "/"
    if (unpacked_dir / "lost+found").exists():
        yield "/lost\\+found"

    for item_path in unpacked_dir.rglob('*'):
        try:
            relative_path = item_path.relative_to(unpacked_dir)
            yield f"/{relative_path.as_posix()}"
        except ValueError:
            continue

def context_patch(original_contexts: Dict[str, str],
                  unpacked_dir: Path,
                  fix_rules: Dict[str, str],
                  partition_name: str) -> Tuple[Dict[str, str], int]:
    compiled_rules: List[Tuple[re.Pattern, str]] = []
    sorted_rules = sorted(fix_rules.items(), key=lambda item: len(item[0]), reverse=True)
    
    for pattern, context in sorted_rules:
        if pattern.startswith(('//', '__comment')):
            continue
        if ' ' in context:
            print(f"[Warning] Invalid context '{context}' for rule '{pattern}' contains a space. Skipping rule.")
            continue
        try:
            compiled_rules.append((re.compile(pattern), context))
        except re.error as e:
            print(f"[Warning] Invalid regex '{pattern}' in fix rules: {e}. Skipping rule.")

    new_contexts = original_contexts.copy()
    newly_added_count = 0
    patched_paths_cache = set()
    
    print("ContextPatcher: Scanning directory and patching contexts...")
    for path_str_relative in scan_dir(unpacked_dir):
        if path_str_relative in new_contexts or path_str_relative in patched_paths_cache:
            continue
        
        path_to_check_for_rules = f"/{partition_name}{path_str_relative}".replace(f"/{partition_name}//", f"/{partition_name}/")
        
        assigned_context = None
        for pattern, context in compiled_rules:
            if pattern.search(path_to_check_for_rules):
                assigned_context = context
                break

        if not assigned_context:
            print(f"  [INFO] No specific rule for '{path_to_check_for_rules}', using safe default.")
            assigned_context = 'u:object_r:system_file:s0'
        
        print(f"  [ADD]  {path_str_relative} -> {assigned_context}")
        new_contexts[path_str_relative] = assigned_context
        patched_paths_cache.add(path_str_relative)
        newly_added_count += 1
    
    return new_contexts, newly_added_count


def main(dir_path_str: str, fs_config_path_str: str, fix_permission_file_str: Optional[str]) -> None:
    dir_path = Path(dir_path_str)
    fs_config_path = Path(fs_config_path_str)
    fix_permission_file = Path(fix_permission_file_str) if fix_permission_file_str else None
    
    try:
        if not dir_path.is_dir():
            print(f"[Error] Directory not found: {dir_path}", file=sys.stderr)
            return
            
        fix_rules = {}
        if fix_permission_file and fix_permission_file.is_file():
            clean_lines = []
            with fix_permission_file.open("r", encoding='utf-8') as f:
                for line in f:
                    stripped_line = line.strip()
                    if not (stripped_line.startswith("//") or stripped_line.startswith('"//"') or '"__comment_"' in stripped_line):
                        clean_lines.append(line)
            
            clean_json_string = "".join(clean_lines)
            try:
                fix_rules = json.loads(clean_json_string)
            except json.JSONDecodeError as e:
                print(f"[ERROR] Failed to parse context_rules.json: {e}")
                fix_rules = {}
        elif fix_permission_file:
            print(f"[Warning] Fix permission file not found: {fix_permission_file}. Proceeding without it.")

        original_contexts = scan_context(fs_config_path.resolve())
        partition_name = fs_config_path.name.replace("_file_contexts", "")

        relative_original_contexts = {}
        prefix_to_strip = f"/{partition_name}"
        for path, context in original_contexts.items():
            if path == prefix_to_strip or path == f"{prefix_to_strip}/":
                relative_original_contexts["/"] = context
            elif path.startswith(prefix_to_strip + '/'):
                relative_path = path[len(prefix_to_strip):]
                relative_original_contexts[relative_path] = context
            else:
                relative_original_contexts[path] = context
        
        new_fs, add_new = context_patch(relative_original_contexts, dir_path, fix_rules, partition_name)

        with fs_config_path.open("w", encoding='utf-8', newline='\n') as f:
            for path in sorted(new_fs.keys()):
                f.write(f"{path} {new_fs[path]}\n")
        
        print(f'ContextPatcher: Successfully added {add_new} new entries. Total entries: {len(new_fs)}.')

    except FileNotFoundError:
        print(f"[Error] Context file not found: {fs_config_path}", file=sys.stderr)
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}", file=sys.stderr)
        raise
