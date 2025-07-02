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
import os
from pathlib import Path
from typing import Dict, Generator

def scanfs(file: str) -> dict:
    filesystem_config = {}
    try:
        with open(file, "r", encoding='utf-8') as file_:
            for line in file_:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if parts:
                    filesystem_config[parts[0]] = parts[1:]
    except FileNotFoundError:
        print(f"[Warning] Original fs_config not found at {file}")
    return filesystem_config

def scan_dir(scan_root: Path) -> Generator[str, None, None]:
    if (scan_root / "lost+found").is_dir():
        yield "lost+found"
    for item_path in scan_root.rglob('*'):
        yield item_path.relative_to(scan_root).as_posix()

def fs_patch(fs_config_data: Dict[str, list], source_dir: str) -> tuple:
    new_fs = fs_config_data.copy()
    new_add = 0
    source_path = Path(source_dir)

    print(f"FsPatcher: The original file has {len(fs_config_data)} entries")

    for rel_path_str in scan_dir(source_path):
        if rel_path_str in new_fs:
            continue
        
        full_disk_path = source_path / rel_path_str
        if not full_disk_path.exists(): continue

        if full_disk_path.is_dir():
            config = ['0', '0', '0755']
        else:
            config = ['0', '0', '0644']

        if "bin/" in rel_path_str or "xbin/" in rel_path_str or rel_path_str.endswith(".sh"):
            config[2] = '0755'
        
        print(f'Add [{rel_path_str} {config}]')
        new_fs[rel_path_str] = config
        new_add += 1

    if '/' not in new_fs:
         new_fs['/'] = ['0', '0', '0755']

    return new_fs, new_add

def main(dir_path: str, fs_config_path: str):
    original_config = scanfs(fs_config_path)
    new_fs_config, new_add = fs_patch(original_config, dir_path)
    
    with open(fs_config_path, "w", encoding='utf-8', newline='\n') as f:
        for path in sorted(new_fs_config.keys()):
            f.write(f"{path} {' '.join(new_fs_config[path])}\n")
            
    print(f'FsPatcher: Added {new_add} entries')
