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
import os.path
import json
import zlib
from ctypes import sizeof, c_char, LittleEndianStructure, byref, memmove, string_at
from enum import Enum
import logging
from pathlib import Path
from _ctypes import addressof
from toml import dump, load
from .posix import symlink, readlink
from typing import Dict, Any, BinaryIO, Union, Tuple

logger = logging.getLogger(__name__)

# The special filename that marks the end of a CPIO archive.
CPIO_TRAILER_NAME = "TRAILER!!!"

# A bitmask representing full permissions (read, write, execute) for user, group, and others.
CPIO_FULL_PERMISSION = 0o7777


class CpioMagicFormat(Enum):
    """
    Enum for CPIO magic numbers, identifying the archive format.
    """
    New = b'070701'  # The "newc" or "SVR4" format
    Crc = b'070702'  # "newc" format with a checksum for file data
    # The old binary format is not supported.
    Old = b'070707'


class CpioModes(Enum):
    """
    Enum for CPIO mode constants, representing file types and permissions.
    These values are part of the `c_mode` field in the CPIO header.
    """
    # --- POSIX File Permissions ---
    C_IRUSR = 0o000400  # read by owner
    C_IWUSR = 0o000200  # write by owner
    C_IXUSR = 0o000100  # execute by owner
    C_IRGRP = 0o000040  # read by group
    C_IWGRP = 0o000020  # write by group
    C_IXGRP = 0o000010  # execute by group
    C_IROTH = 0o000004  # read by others
    C_IWOTH = 0o000002  # write by others
    C_IXOTH = 0o000001  # execute by others

    # --- Special Mode Bits ---
    C_ISUID = 0o004000  # set user ID
    C_ISGID = 0o002000  # set group ID
    C_ISVTX = 0o001000  # sticky bit

    # --- File Type Constants ---
    C_ISBLK = 0o060000   # Block Special
    C_ISCHR = 0o020000   # Character Special
    C_ISDIR = 0o040000   # Directory
    C_ISFIFO = 0o010000  # FIFO Special
    C_ISSOCK = 0o0140000 # Socket
    C_ISLNK = 0o0120000  # Symbolic Link
    C_ISCTG = 0o0110000  # Contiguous File (implementation-dependent)
    C_ISREG = 0o0100000  # Regular File

    # A bitmask to isolate the file type from the full c_mode value.
    MaskAllTypes = C_ISBLK | C_ISCHR | C_ISDIR | C_ISFIFO | C_ISSOCK | C_ISLNK | C_ISCTG | C_ISREG


class BasicStruct(LittleEndianStructure):
    """
    A base class for ctypes.LittleEndianStructure to provide common packing/unpacking utilities.
    """
    @property
    def _size(self) -> int:
        """Returns the size of the structure in bytes."""
        return sizeof(type(self))

    def __len__(self) -> int:
        """Returns the size of the structure in bytes."""
        return self._size

    def unpack(self, data: bytes) -> 'BasicStruct':
        """
        Populates the structure's fields from a bytes object.

        Args:
            data: A bytes or bytearray object to unpack from.

        Returns:
            The instance of the structure itself.

        Raises:
            Exception: If the input data is smaller than the structure size or not bytes/bytearray.
        """
        if len(data) < self._size:
            raise ValueError("Input data size is less than the structure size.")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Input data must be a bytes or bytearray object.")

        memmove(byref(self), data, self._size)
        return self

    def pack(self) -> bytes:
        """
        Packs the structure's fields into a bytes object.

        Returns:
            A bytes object representing the structure's data.
        """
        return string_at(addressof(self), sizeof(self))


class CpioHeader(BasicStruct):
    """
    Represents the CPIO 'newc' format header structure (110 bytes).
    Fields are stored as 8-byte hexadecimal ASCII strings.
    """
    _packed_ = 1
    _fields_ = [
        ("c_magic", c_char * 6),     # Magic number (e.g., "070701")
        ("c_ino", c_char * 8),       # Inode number
        ("c_mode", c_char * 8),      # File mode and type
        ("c_uid", c_char * 8),       # User ID
        ("c_gid", c_char * 8),       # Group ID
        ("c_nlink", c_char * 8),     # Number of links
        ("c_mtime", c_char * 8),     # Modification time (Unix timestamp)
        ("c_filesize", c_char * 8),  # Size of the file data
        ("c_dev_maj", c_char * 8),   # Major device number
        ("c_dev_min", c_char * 8),   # Minor device number
        ("c_rdev_maj", c_char * 8),  # Major device number for special files
        ("c_rdev_min", c_char * 8),  # Minor device number for special files
        ("c_namesize", c_char * 8),  # Size of the filename (including null terminator)
        ("c_chksum", c_char * 8),    # Checksum (0 for 'newc', CRC for 'crc' format)
    ]

    def is_valid(self) -> bool:
        """
        Performs a basic sanity check on the header.

        It verifies that essential size fields contain valid hexadecimal characters,
        which helps filter out padding or corrupted data between entries.

        Returns:
            True if key fields can be parsed as integers, False otherwise.
        """
        try:
            # ctype fields are bytes, they must be decoded before conversion.
            int(self.c_namesize.decode('ascii'), 16)
            int(self.c_filesize.decode('ascii'), 16)
            return True
        except (ValueError, TypeError, UnicodeDecodeError):
            # A conversion error indicates the header is likely invalid.
            return False


def parser_c_mode(data: Union[str, bytes]) -> Tuple[CpioModes, int]:
    """
    Parses a c_mode hex string or bytes into a file type and permission mask.

    Args:
        data: An 8-character hex string or ASCII bytes representing the c_mode field.

    Returns:
        A tuple containing:
            - file_type: The file type as a CpioModes enum member.
            - permissions: The permission bits as an integer (masked with 0o7777).

    Raises:
        ValueError: If the input data has an incorrect length or format.
    """
    # 1. Safely decode if input is bytes.
    if isinstance(data, bytes):
        data = data.decode('ascii', errors='replace')

    # 2. Validate length.
    if len(data) != 8:
        raise ValueError(f"Invalid c_mode length: expected 8 characters, got {len(data)}")

    # 3. Parse hex string to integer.
    # No try/except needed, as int() will raise a ValueError on failure, which is desired.
    c_mode = int(data, 16)

    # 4. Isolate file type and mode bits.
    file_type_val = c_mode & CpioModes.MaskAllTypes.value
    file_mode = c_mode & CPIO_FULL_PERMISSION

    # The CpioModes enum constructor will find the member by value or raise a ValueError.
    return CpioModes(file_type_val), file_mode


def pack_c_mode(file_type: int, file_mode: Union[int, str]) -> str:
    """
    Packs a file type and permission mode into a CPIO c_mode hex string.

    Args:
        file_type: The integer value of the file type (e.g., CpioModes.C_ISREG.value).
        file_mode: The file permissions, either as an octal string (e.g., "755") or an integer.

    Returns:
        An 8-character, zero-padded hexadecimal string for the c_mode field.
    """
    if isinstance(file_mode, str):
        file_mode = int(file_mode, 8)
    return f"{(file_mode | file_type):08x}"


def calc_crc(data: bytes) -> int:
    """
    Calculates a simple checksum by summing all byte values.

    Note: This is a legacy checksum method and is not a standard CRC32.
    It is not currently used by the main extraction logic, which favors zlib.crc32.

    Args:
        data: The bytes object to checksum.

    Returns:
        The calculated checksum as an integer.
    """
    crc = sum(data)
    if crc >= 0xffffffff:
        crc &= 0xffffffff
    return crc


class ExtractionError(Exception):
    """Custom exception for critical extraction errors when running in strict mode."""
    pass

# ==============================================================================
# --- Helper Functions for Clean and Reusable Extraction Logic ---
# ==============================================================================


def _read_padding(f: BinaryIO, size: int) -> None:
    """Reads and discards padding bytes from a stream to align to a 4-byte boundary."""
    if padding := (4 - (size % 4)) % 4:
        f.read(padding)


def _validate_path(base_path: Path, path_name: str) -> Path:
    """
    Validates a path against path traversal attacks and returns a safe, absolute Path object.

    It ensures that the resolved path of the entry is still within the intended
    extraction directory.

    Args:
        base_path: The absolute path of the extraction directory.
        path_name: The relative path of the file from the archive.

    Returns:
        A safe, absolute Path object for the destination.

    Raises:
        ExtractionError: If a path traversal attempt is detected.
    """
    # Normalize the path to resolve components like '..'
    full_path = base_path / path_name
    resolved_path_str = os.path.normpath(str(full_path))
    # Check if the resolved path still starts with the base extraction directory.
    if not resolved_path_str.startswith(str(base_path)):
        raise ExtractionError(f"Path traversal attempt detected: '{path_name}'")
    return Path(resolved_path_str)


def _apply_metadata(path: Path, mode: int, uid: int, gid: int, mtime: int, is_symlink: bool) -> None:
    """
    Applies filesystem metadata (mode, ownership, timestamps) to a file, directory, or symlink.

    This function attempts to set permissions, ownership, and modification times. It will
    log warnings on failure (e.g., due to permissions) rather than raising an exception.
    It also handles OS-specific differences for symlinks.

    Args:
        path: The path to the created filesystem object.
        mode: The file permission mode (e.g., 0o755).
        uid: The user ID.
        gid: The group ID.
        mtime: The modification time (Unix timestamp).
        is_symlink: True if the path is a symbolic link.
    """
    try:
        # Don't chmod a symlink itself, only its target.
        if not is_symlink:
            os.chmod(path, mode)
        # Use follow_symlinks=False where supported to act on the link itself.
        if os.utime in os.supports_follow_symlinks:
            os.utime(path, (mtime, mtime), follow_symlinks=False)
        else:
            if not is_symlink:
                os.utime(path, (mtime, mtime))
        # chown is not available on Windows.
        if os.name != 'nt':
            if os.chown in os.supports_follow_symlinks:
                os.chown(path, uid, gid, follow_symlinks=False)
            elif not is_symlink:
                os.chown(path, uid, gid)
    except OSError as e:
        logger.warning(f"Failed to apply metadata for '{path}': {e}")


def _extract_regular_file(f: BinaryIO, path: Path, size: int, check_crc: bool, header: CpioHeader) -> None:
    """
    Streams a regular file from the archive to disk to conserve memory.

    It reads the file in chunks rather than loading the entire file into memory.
    If `check_crc` is enabled, it calculates the CRC32 checksum on the fly.

    Args:
        f: The input file-like object for the archive.
        path: The destination path for the file.
        size: The size of the file to extract.
        check_crc: If True, validate the file's CRC32 checksum against the header.
        header: The CpioHeader object for the current entry.

    Raises:
        ExtractionError: On I/O errors or if the archive ends unexpectedly.
    """
    crc32 = 0
    try:
        with open(path, 'wb') as out_f:
            remaining = size
            while remaining > 0:
                # Read in chunks (e.g., 1MB) to handle large files efficiently.
                chunk_size = min(remaining, 1024 * 1024)
                data = f.read(chunk_size)
                if not data:
                    raise ExtractionError(f"Unexpected end of archive while reading '{path.name}'")
                if check_crc:
                    crc32 = zlib.crc32(data, crc32)
                out_f.write(data)
                remaining -= len(data)
    except OSError as e:
        raise ExtractionError(f"Error writing file '{path.name}': {e}") from e

    if check_crc:
        try:
            expected_crc = int(header.c_chksum.decode('ascii'), 16)
            if crc32 != expected_crc:
                logger.warning(f"CRC check failed for file '{path.name}'.")
        except (ValueError, UnicodeDecodeError):
            logger.warning(f"Invalid CRC value in header for '{path.name}'.")


def _create_symlink(path: Path, f: BinaryIO, size: int, base_path: Path) -> None:
    """
    Creates a symbolic link with security checks for the target path.

    It reads the link target from the archive, decodes it, and validates that
    it does not point outside the extraction directory. It includes a fallback
    mechanism for different text encodings.

    Args:
        path: The path where the symbolic link should be created.
        f: The input file-like object for the archive.
        size: The size of the link target string.
        base_path: The absolute path of the extraction directory for validation.

    Raises:
        ExtractionError: If the link target is too long, insecure, or cannot be created.
    """
    if size > 4096:  # A reasonable limit for link targets.
        raise ExtractionError(f"Symbolic link target is too long for '{path.name}': {size} bytes.")

    target_bytes = f.read(size).split(b'\x00')[0]

    target_str = None
    try:
        # Assume UTF-8 first, as it's the most common.
        target_str = target_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # If UTF-8 fails, try other common encodings.
        encodings_to_try = ['gbk', 'windows-1251', 'cp866', 'windows-1252']
        for encoding in encodings_to_try:
            try:
                target_str = target_bytes.decode(encoding)
                logger.info(f"Symlink target for '{path.name}' decoded using '{encoding}': {target_str}")
                break
            except UnicodeDecodeError:
                continue
        # If all else fails, decode with a lossless fallback.
        if target_str is None:
            target_str = target_bytes.decode('utf-8', errors='surrogateescape')
            logger.warning(
                f"Could not determine encoding for symlink target '{path.name}'. "
                f"Used 'surrogateescape'. Original bytes: {target_bytes.hex(' ')}"
            )

    # Security check: Ensure the link target doesn't point outside the extraction root.
    target_full_path = os.path.normpath(str(path.parent / target_str))
    if not target_full_path.startswith(str(base_path)):
        raise ExtractionError(f"Insecure symlink target detected: '{path.name}' -> '{target_str}'")

    try:
        # Ensure any existing file/link at the destination is removed first.
        path.unlink(missing_ok=True)
        symlink(target_str, str(path))
    except OSError as e:
        raise ExtractionError(f"Error creating symbolic link '{path.name}': {e}") from e

# ==============================================================================
# --- Main Orchestration Function ---
# ==============================================================================


def extract(filename: str, outputdir: str, output_info: str, check_crc: bool = False, strict: bool = False) -> None:
    """
    Safely extracts files from a CPIO archive using best practices for security,
    robustness, and memory management. Compatible with Python 3.7+.

    Args:
        filename: Path to the input CPIO archive.
        outputdir: Path to the directory where files will be extracted.
        output_info: Path to write a JSON file containing the metadata of all entries.
        check_crc: If True, validate file checksums (for CRC-enabled CPIO formats).
        strict: If True, any error during entry extraction will stop the entire process.
                If False (default), errors are logged, and the process continues.
    """
    MAX_NAME_SIZE, MAX_FILE_SIZE = 4096, 10 * 1024**3  # 4KB for name, 10GB for file
    header_size = len(CpioHeader())
    info: Dict[str, Any] = {}
    count = 0

    try:
        # Resolve the output path and ensure it's a directory.
        abs_output_path = Path(outputdir).resolve(strict=True)
    except FileNotFoundError:
        Path(outputdir).mkdir(parents=True, exist_ok=True)
        abs_output_path = Path(outputdir).resolve(strict=True)

    logger.info(f"Starting extraction from '{filename}' to '{abs_output_path}'")

    with Path(filename).open('rb') as f:
        while True:
            file_size = 0
            name = ""
            body_start_pos = 0
            try:
                # Read the next header block.
                header_bytes = f.read(header_size)
                if len(header_bytes) < header_size:
                    # Not enough bytes for a header, assume end of file.
                    break

                header = CpioHeader()
                header.unpack(header_bytes)

                # Skip null-byte padding that can exist between entries.
                if header.c_magic == b'\x00' * 6:
                    continue

                # Perform a quick sanity check on the header.
                if not header.is_valid():
                    logger.debug("Detected an invalid header block, skipping.")
                    continue

                namesize = int(header.c_namesize.decode('ascii'), 16)
                file_size = int(header.c_filesize.decode('ascii'), 16)

                # Security: Prevent decompression bombs and path length issues.
                if namesize > MAX_NAME_SIZE or file_size > MAX_FILE_SIZE:
                    raise ExtractionError(f"Exceeded size limit for name ({namesize}) or file ({file_size}).")

                # Read the filename and strip the null terminator.
                name_bytes = f.read(namesize).split(b'\x00')[0]

                # Attempt to decode the filename with fallbacks.
                name = None
                try:
                    name = name_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    encodings_to_try = ['gbk', 'windows-1251', 'cp866', 'windows-1252']
                    for encoding in encodings_to_try:
                        try:
                            name = name_bytes.decode(encoding)
                            logger.info(f"Filename decoded using '{encoding}': {name}")
                            break
                        except UnicodeDecodeError:
                            continue
                    if name is None:
                        name = name_bytes.decode('utf-8', errors='surrogateescape')
                        logger.warning(
                            "Could not determine filename encoding. Using 'surrogateescape' to preserve data. "
                            f"Original bytes (hex): {name_bytes.hex(' ')}"
                        )

                # Skip header padding.
                _read_padding(f, header_size + namesize)

                # Check for the CPIO end-of-archive marker.
                if name == CPIO_TRAILER_NAME:
                    break

                body_start_pos = f.tell()

                # Skip entries with no name (should not happen in valid archives).
                if not name:
                    if file_size > 0:
                        f.seek(file_size, os.SEEK_CUR)
                    _read_padding(f, file_size)
                    continue

                # Security: Validate the destination path.
                full_dest_path = _validate_path(abs_output_path, name)

                # Parse header metadata.
                file_type, file_mode = parser_c_mode(header.c_mode)
                uid = int(header.c_uid.decode('ascii'), 16)
                gid = int(header.c_gid.decode('ascii'), 16)
                mtime = int(header.c_mtime.decode('ascii'), 16)
                c_nlink = int(header.c_nlink.decode('ascii'), 16)
                c_ino = int(header.c_ino.decode('ascii'), 16)

                # Store metadata for the final JSON report.
                info[name] = {
                    'file_type': file_type.value, 'file_mode': file_mode,
                    'uid': uid, 'gid': gid, 'mtime': mtime, 'c_nlink': c_nlink,
                    'c_ino': c_ino, 'size': file_size
                }

                # Ensure the parent directory exists.
                full_dest_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract based on file type.
                if file_type == CpioModes.C_ISREG:
                    _extract_regular_file(f, full_dest_path, file_size, check_crc, header)
                elif file_type == CpioModes.C_ISLNK:
                    _create_symlink(full_dest_path, f, file_size, abs_output_path)
                elif file_type == CpioModes.C_ISDIR:
                    full_dest_path.mkdir(exist_ok=True)
                else:  # For other types like FIFO, block/char device, just skip the body.
                    if file_size > 0:
                        f.seek(file_size, os.SEEK_CUR)

                # Apply permissions, ownership, and timestamps.
                _apply_metadata(full_dest_path, file_mode, uid, gid, mtime, file_type == CpioModes.C_ISLNK)
                _read_padding(f, file_size)

                count += 1
                logger.debug(f"Extracted: {name}")
                if count > 0 and count % 1000 == 0:
                    logger.info(f"Processed {count} entries...")

            except (ExtractionError, ValueError, OSError, zlib.error) as e:
                if strict:
                    raise ExtractionError(f"Critical error while processing entry '{name}': {e}") from e
                logger.error(f"Error processing entry '{name}', skipping: {e}")
                # Attempt to recover by seeking past the corrupted entry's data.
                if body_start_pos > 0:
                    current_pos = f.tell()
                    bytes_read_from_body = current_pos - body_start_pos
                    remaining_to_skip = file_size - bytes_read_from_body
                    if remaining_to_skip > 0:
                        f.seek(remaining_to_skip, os.SEEK_CUR)
                elif file_size > 0:
                    f.seek(file_size, os.SEEK_CUR)
                # Ensure we still account for padding.
                _read_padding(f, file_size)
                continue

    logger.info(f"Extraction complete. Total entries processed: {count}")
    try:
        Path(output_info).write_text(json.dumps(info, indent=4), encoding='utf-8')
        logger.info(f"Metadata saved to {output_info}")
    except IOError as e:
        logger.error(f"Failed to write JSON info file: {e}")


def scan_dir(folder: str, return_trailer: bool = True) -> str:
    """
    Scans a directory recursively and yields relative paths for CPIO archive entries.

    The scan order is important for creating a valid archive:
    1. Yields "." to represent the root directory of the archive.
    2. Walks the directory tree, yielding subdirectory and file paths.
    3. (Optional) Yields the CPIO trailer name at the end.

    Args:
        folder: The absolute or relative path to the directory to scan.
        return_trailer: If True, yields CPIO_TRAILER_NAME as the final entry.

    Yields:
        Relative paths of directories and files, using forward slashes.
    """
    # 1. First, yield the root directory entry.
    yield "."

    # 2. Then, walk through all nested items.
    for root, dirs, files in os.walk(folder, topdown=True):
        # Process subdirectories.
        for dir_name in dirs:
            full_path = os.path.join(root, dir_name)
            relative_path = os.path.relpath(full_path, folder)
            # Normalize path separators for consistency.
            yield relative_path.replace('\\', '/')

        # Process files.
        for file_name in files:
            full_path = os.path.join(root, file_name)
            relative_path = os.path.relpath(full_path, folder)
            yield relative_path.replace('\\', '/')

    # 3. Finally, yield the trailer if requested.
    if return_trailer:
        yield CPIO_TRAILER_NAME


def repack(input_dir: str, config_file: str, output_file: str, magic_type: CpioMagicFormat = None) -> int:
    """
    Repacks a directory into a CPIO archive using metadata from a configuration file.

    This function prioritizes metadata from the JSON config file to ensure the repacked
    archive is as identical as possible to the original. If metadata for an entry is
    missing, it generates it from the file on disk.

    Args:
        input_dir: The directory containing the files to be packed.
        config_file: The JSON file with metadata from the original extraction.
        output_file: The path for the new CPIO archive.
        magic_type: The CPIO magic format to use. Defaults to 'newc'.

    Returns:
        0 on success, 1 on failure.
    """
    ino_sum = 0
    if not magic_type:
        magic_type = CpioMagicFormat.New.value

    try:
        with open(config_file, 'r', encoding='utf-8') as con:
            cpio_info = json.load(con)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error reading or parsing config file '{config_file}': {e}")
        return 1

    # Ensure the output directory exists.
    output_dirname = os.path.dirname(output_file)
    if not os.path.exists(output_dirname) and output_dirname:
        os.makedirs(output_dirname, exist_ok=True)

    def _write_with_padding(stream: BinaryIO, data: bytes):
        """Helper to write data and then null-byte padding to a 4-byte boundary."""
        stream.write(data)
        if padding := len(data) % 4:
            stream.write(b'\x00' * (4 - padding))

    try:
        with open(output_file, 'wb') as out:
            header = CpioHeader()
            # Iterate through files and directories provided by the scanner.
            for entry in scan_dir(input_dir):

                # Handle the special trailer entry.
                if entry == CPIO_TRAILER_NAME:
                    logger.info('Adding: TRAILER!!!')
                    ino_sum += 1

                    trailer_header = CpioHeader()
                    trailer_header.c_magic = magic_type
                    trailer_header.c_ino = f"{ino_sum:08x}".encode('utf-8')
                    trailer_header.c_namesize = f"{len(CPIO_TRAILER_NAME.encode('utf-8')) + 1:08x}".encode('utf-8')

                    header_and_name = trailer_header.pack() + CPIO_TRAILER_NAME.encode('utf-8') + b'\x00'
                    _write_with_padding(out, header_and_name)
                    continue

                # Get metadata from the JSON file, or an empty dict if not found.
                value = cpio_info.get(entry, {})
                path_on_disk = os.path.join(input_dir, entry) if entry != "." else input_dir

                # Fallback: if metadata is missing, get it from the live filesystem.
                if 'file_type' not in value:
                    logger.warning(f"Metadata for '{entry}' not found in JSON. Generating from disk.")
                    if os.path.isdir(path_on_disk):
                        value['file_type'], value['file_mode'] = CpioModes.C_ISDIR.value, 0o755
                    elif os.path.islink(path_on_disk):
                        value['file_type'], value['file_mode'] = CpioModes.C_ISLNK.value, 0o777
                    elif os.path.isfile(path_on_disk):
                        value['file_type'], value['file_mode'] = CpioModes.C_ISREG.value, 0o644
                    else:
                        logger.error(f"Unknown file type for '{entry}'. Skipping.")
                        continue

                logger.info(f'Adding: {entry}')
                ino_sum += 1

                # Populate the header fields.
                header.c_magic = magic_type
                header.c_ino = f"{value.get('c_ino', ino_sum):08x}".encode('utf-8')
                # Use pre-computed c_mode if available, otherwise pack it.
                if value.get('c_mode') is not None:
                    header.c_mode = f"{value['c_mode']:08x}".encode('utf-8')
                else:
                    header.c_mode = pack_c_mode(value['file_type'], value['file_mode']).encode('utf-8')

                parsed_type, _ = parser_c_mode(header.c_mode)
                is_file = (parsed_type == CpioModes.C_ISREG)
                is_link = (parsed_type == CpioModes.C_ISLNK)

                header.c_nlink = f"{value.get('c_nlink', 1):08x}".encode('utf-8')
                header.c_uid = f"{value.get('c_uid', 0):08x}".encode('utf-8')
                header.c_gid = f"{value.get('c_gid', 0):08x}".encode('utf-8')
                header.c_mtime = f"{value.get('c_mtime', 0):08x}".encode('utf-8')

                # Prioritize original file size from JSON to maintain integrity.
                filesize = 0
                if value.get('size') is not None:
                    filesize = value['size']
                    logger.debug(f"Using original size {filesize} from JSON for '{entry}'")
                else:
                    logger.warning(f"Size for '{entry}' not found in JSON, recalculating from disk...")
                    if is_file:
                        filesize = os.path.getsize(path_on_disk)
                    elif is_link:
                        filesize = len(readlink(path_on_disk).encode('utf-8'))

                header.c_filesize = f"{filesize:08x}".encode('utf-8')
                header.c_dev_maj = f"{value.get('c_dev_maj', 0):08x}".encode('utf-8')
                header.c_dev_min = f"{value.get('c_dev_min', 0):08x}".encode('utf-8')
                header.c_rdev_maj = f"{value.get('c_rdev_maj', 0):08x}".encode('utf-8')
                header.c_rdev_min = f"{value.get('c_rdev_min', 0):08x}".encode('utf-8')
                header.c_namesize = f"{len(entry.encode('utf-8')) + 1:08x}".encode('utf-8')
                header.c_chksum = f"{value.get('c_chksum', 0):08x}".encode('utf-8')

                # Write header and name, with padding.
                header_and_name = header.pack() + entry.encode('utf-8') + b'\x00'
                _write_with_padding(out, header_and_name)

                # Write file content or symlink target, with padding.
                if is_file:
                    with open(path_on_disk, 'rb') as f_in:
                        content = f_in.read()
                        _write_with_padding(out, content)
                elif is_link:
                    content = readlink(path_on_disk).encode('utf-8')
                    _write_with_padding(out, content)

    except IOError as e:
        logger.error(f"Error writing to output file '{output_file}': {e}")
        return 1
    except Exception as e:
        # Log the full exception with traceback for easier debugging.
        logger.exception(f"An unexpected error occurred during repacking: {e}")
        return 1

    logger.info(f'{ino_sum} inodes packed.')
    return 0
