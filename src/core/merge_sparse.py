# src/core/merge_sparse.py

"""
Handles the merging of Android sparse image chunks into a single raw image file.

This module provides functionality to detect, sort, and combine split image
files (e.g., `super_sparsechunk.0`, `super_sparsechunk.1`, etc.) into a
complete image (e.g., `super.img`).

It employs a hybrid strategy:
1. It uses the `simg2img` tool to decompress the first sparse chunk.
2. It then directly concatenates the subsequent chunks to the output file.

This approach is efficient as it avoids unnecessary processing on chunks that
are often raw data segments following the initial sparse-formatted header.

The main entry point is the `main()` function, which orchestrates the entire
process, while `smart_merge_generator()` provides the core logic with progress
reporting.
"""

import os
import re
import logging
from typing import List, Optional, Generator, Tuple

# Set up a logger for this module
logger = logging.getLogger(__name__)


def natural_sort_key(s: str) -> List:
    """
    Creates a sort key for "natural" sorting of strings containing numbers.

    This allows, for example, 'file10.chunk' to be sorted after 'file2.chunk'
    instead of before it (which would happen with standard lexical sorting).

    Args:
        s: The input string to create a sort key for.

    Returns:
        A list of strings and integers that can be used as a sort key.
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split('([0-9]+)', s)]


def find_simg2img_executable(settings) -> Optional[str]:
    """
    Locates the `simg2img` executable within the configured tool directory.

    It checks for both `simg2img.exe` (Windows) and `simg2img` (Linux/macOS)
    in the path specified by `settings.tool_bin`.

    Args:
        settings: A configuration object that must have a `tool_bin` attribute
                  pointing to the directory with the tool.

    Returns:
        The name of the executable if found, otherwise None.
    """
    tool_bin_path = getattr(settings, 'tool_bin', '')
    if not tool_bin_path or not os.path.isdir(tool_bin_path):
        logging.error("simg2img binary path ('tool_bin') is not configured or does not exist.")
        return None
    for name in ('simg2img.exe', 'simg2img'):
        if os.path.exists(os.path.join(tool_bin_path, name)):
            return name
    logging.error("simg2img executable not found in the configured tool_bin path.")
    return None


def _find_and_sort_segments(project_path: str) -> List[str]:
    """
    Finds and sorts all image segment files in a given directory.

    It uses a regex to identify files ending in common chunk patterns like
    `_sparsechunk.N`, `.img.N`, etc., and then sorts them using natural sort.

    Args:
        project_path: The directory to search for segment files.

    Returns:
        A naturally sorted list of full paths to the segment files.
    """
    # Regex to match common Android sparse chunk naming conventions.
    segment_pattern = re.compile(r'.*(_sparsechunk|sparse_chunk|\.chunk|\.img)\.\d+$')
    all_files = os.listdir(project_path)
    segment_files = [
        f for f in all_files
        if segment_pattern.match(f) and os.path.isfile(os.path.join(project_path, f))
    ]
    segment_files.sort(key=natural_sort_key)
    return [os.path.join(project_path, f) for f in segment_files]


def _delete_source_segments(segment_paths: List[str], lang):
    """
    Deletes the source segment files after a successful merge.

    Args:
        segment_paths: A list of file paths to delete.
        lang: A language object for localized logging messages.
    """
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
    """
    A generator that merges sparse image chunks, yielding progress.

    This function implements the core "smart merge" logic. It first uses the
    `simg2img` tool to process the first segment (which contains the sparse
    header), creating the initial output file. It then appends all subsequent
    segments directly to this file, which is much faster than processing each
    one with `simg2img`.

    Args:
        project_path: The path to the directory containing the segment files.
        output_name: The desired filename for the final merged image.
        utils: A shared utilities object containing settings, language strings,
               and helper functions like `call` and `warn_win`.

    Yields:
        A tuple `(percentage, output_path)`, where `percentage` is the
        current progress (0-100) and `output_path` is the path to the
        in-progress output file.

    Returns:
        The full path to the successfully merged file, or `None` if an
        error occurred.
    """
    lang = utils.lang
    output_path = os.path.join(project_path, output_name)

    executable_name = find_simg2img_executable(utils.settings)
    if not executable_name:
        utils.warn_win(getattr(lang, 'simg2img_not_found_error', 'simg2img not found.'))
        return None

    segment_file_paths = _find_and_sort_segments(project_path)
    if not segment_file_paths:
        logging.info(f"> {getattr(lang, 't_no_file_segments_found', 'No segments found.')}")
        return  # Gracefully exit the generator if no segments are found.

    logging.info(f"> {getattr(lang, 'segments_found_msg', 'Found segments:')}")
    for f in segment_file_paths:
        logging.info(f"  - {os.path.basename(f)}")

    total_size = sum(os.path.getsize(p) for p in segment_file_paths)
    if total_size == 0:
        logging.warning("Total size of segments is 0. Nothing to merge.")
        return

    processed_size = 0

    # Step 1: Process the first segment using simg2img to handle the sparse format header.
    first_segment = segment_file_paths[0]
    command = [executable_name, first_segment, output_path]
    logging.info(f"\n> {getattr(lang, 'running_command_msg', 'Running command:').format(command=' '.join(command))}")
    logging.info(f"> {getattr(lang, 'processing_segment', 'Processing: {filename}').format(filename=os.path.basename(first_segment))}")
    return_code = utils.call(command, out=False)

    if return_code != 0:
        utils.warn_win(getattr(lang, 'merge_fail_initial', 'Initial merge failed for {filename}').format(filename=os.path.basename(first_segment)))
        # Clean up the potentially created (but failed) output file.
        if os.path.exists(output_path):
            os.remove(output_path)
        return None

    processed_size += os.path.getsize(first_segment)
    yield (int(processed_size * 100 / total_size), output_path)

    # Step 2: Append the rest of the segments directly. This is much faster.
    # The output file is opened in "append binary" mode.
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
        # Clean up the partially merged file on append failure.
        if os.path.exists(output_path):
            os.remove(output_path)
        return None

    # On success, the generator finishes and returns the final path.
    return output_path


def main(project_path: str, output_name: str = "super.img", delete_source: bool = False, progress_callback=None, utils=None):
    """
    Main function to orchestrate the sparse image merging process.

    This function is the primary public entry point. It wraps the
    `smart_merge_generator`, handles pre-flight checks, reports progress
    via a callback, and manages final success/failure notifications and
    optional cleanup of source files.

    Args:
        project_path (str): The directory containing the image segments.
        output_name (str): The name of the final merged image file.
                           Defaults to "super.img".
        delete_source (bool): If True, the original segment files will be
                              deleted after a successful merge. Defaults to False.
        progress_callback (callable, optional): A function to call with progress
                                                updates. It receives an integer
                                                percentage (0-100) or -1 on error.
                                                Defaults to None.
        utils (object, optional): A shared utilities object. If not provided, it will
                                  be imported locally. Defaults to None.
    """
    if not utils:
        # Lazy import if utils object is not passed in.
        from . import utils as local_utils
        utils = local_utils

    lang = utils.lang
    output_path = os.path.join(project_path, output_name)

    if not os.path.isdir(project_path):
        utils.warn_win(getattr(lang, 'project_path_error', 'Project path does not exist or is not a directory: {project_path}').format(project_path=project_path))
        return

    # If the final file already exists, skip the merge process.
    if os.path.exists(output_path):
        logging.info(f"> {getattr(lang, 'merge_skipped_exists', 'Output file {output_name} already exists. Skipping merge.').format(output_name=output_name)}")
        if progress_callback:
            progress_callback(100)
        return

    logging.info(f"> {getattr(lang, 'searching_for_segments_msg', 'Searching for image segments in: {project_path}').format(project_path=project_path)}")

    try:
        final_output = None
        # Drive the generator to perform the merge.
        for percentage, path in smart_merge_generator(project_path, output_name, utils):
            if progress_callback:
                progress_callback(percentage)
            final_output = path

        # This logic handles the outcome after the generator has finished.
        # We check `final_output` to see if the generator completed without returning None.
        # If it's `None`, it means an error occurred, which was already reported via
        # `utils.warn_win` inside the generator.
        if final_output:
            if os.path.exists(final_output):
                if progress_callback:
                    progress_callback(100)
                success_msg = getattr(lang, 'merge_success_msg', 'Merge successful. Output: {output_path}').format(output_path=final_output)
                logging.info(f"> {success_msg}")
                utils.info_win(success_msg)

                if delete_source:
                    # We need to find the segments again for deletion.
                    source_segments = _find_and_sort_segments(project_path)
                    _delete_source_segments(source_segments, lang)
            # If `final_output` is not None but the file doesn't exist, it indicates a
            # failure case that was already handled inside the generator (e.g., file cleanup).
            # No further action is needed here.

    except Exception as e:
        # A final catch-all for any truly unexpected errors during the process.
        logging.exception("An unexpected error occurred in merge_sparse.main")
        error_msg = getattr(lang, 'unexpected_merge_error', 'An unexpected error occurred during merge: {error}').format(error=e)
        utils.warn_win(error_msg)
        if progress_callback:
            progress_callback(-1) # Signal an error state to the UI.