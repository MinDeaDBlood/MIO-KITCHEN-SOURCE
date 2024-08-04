# Copyright (C) 2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint: disable=line-too-long
from __future__ import print_function
import os
import tempfile
from hashlib import sha1
from subprocess import call, STDOUT
from threading import Thread, Lock
from collections import OrderedDict
from functools import total_ordering
from rangelib import RangeSet
from itertools import chain

__all__ = ["EmptyImage", "DataImage", "BlockImageDiff"]

class Settings:
    cache_size = None
    stash_threshold = 0.8


def compute_patch(src, tgt, imgdiff=False):
    with tempfile.NamedTemporaryFile(delete=False) as src_file, \
         tempfile.NamedTemporaryFile(delete=False) as tgt_file, \
         tempfile.NamedTemporaryFile(delete=False) as patch_file:

        src_path = src_file.name
        tgt_path = tgt_file.name
        patch_path = patch_file.name

        src_file.write(b''.join(src))
        tgt_file.write(b''.join(tgt))

    try:
        os.unlink(patch_path)
        cmd = ["imgdiff", "-z", src_path, tgt_path, patch_path] if imgdiff else ["bsdiff", src_path, tgt_path, patch_path]
        return_code = call(cmd, stdout=open(os.devnull, 'w'), stderr=STDOUT)

        if return_code != 0:
            raise ValueError(f"Diff failed with error code: {return_code}")

        with open(patch_path, "rb") as patch_file:
            return patch_file.read()
    finally:
        for temp_file in [src_path, tgt_path, patch_path]:
            try:
                os.unlink(temp_file)
            except OSError:
                pass


class Image:
    def ReadRangeSet(self, ranges):
        raise NotImplementedError

    def TotalSha1(self, include_clobbered_blocks=False):
        raise NotImplementedError


class EmptyImage(Image):
    """A zero-length image."""
    blocksize = 4096
    care_map = RangeSet()
    clobbered_blocks = RangeSet()
    extended = RangeSet()
    total_blocks = 0
    file_map = {}

    def ReadRangeSet(self, ranges):
        return ()

    def TotalSha1(self, include_clobbered_blocks=False):
        assert self.clobbered_blocks.size() == 0
        return sha1().hexdigest()


class DataImage(Image):
    """An image wrapped around a single string of data."""

    def __init__(self, data, trim=False, pad=False):
        self.data = data
        self.blocksize = 4096

        assert not (trim and pad)

        partial = len(self.data) % self.blocksize
        padded = False
        if partial > 0:
            if trim:
                self.data = self.data[:-partial]
            elif pad:
                self.data += b'\0' * (self.blocksize - partial)
                padded = True
            else:
                raise ValueError(
                    f"data for DataImage must be multiple of {self.blocksize:d} bytes unless trim or pad is specified")

        assert len(self.data) % self.blocksize == 0

        self.total_blocks = len(self.data) // self.blocksize
        self.care_map = RangeSet(data=(0, self.total_blocks))
        
        clobbered_blocks = [self.total_blocks - 1, self.total_blocks] if padded else []
        self.clobbered_blocks = RangeSet(data=clobbered_blocks)
        self.extended = RangeSet()

        zero_blocks = []
        nonzero_blocks = []
        reference = b'\0' * self.blocksize

        for i in range(self.total_blocks - 1 if padded else self.total_blocks):
            d = self.data[i * self.blocksize: (i + 1) * self.blocksize]
            if d == reference:
                zero_blocks.append(i)
                zero_blocks.append(i + 1)
            else:
                nonzero_blocks.append(i)
                nonzero_blocks.append(i + 1)

        assert zero_blocks or nonzero_blocks or clobbered_blocks

        self.file_map = {}
        if zero_blocks:
            self.file_map["__ZERO"] = RangeSet(data=zero_blocks)
        if nonzero_blocks:
            self.file_map["__NONZERO"] = RangeSet(data=nonzero_blocks)
        if clobbered_blocks:
            self.file_map["__COPY"] = RangeSet(data=clobbered_blocks)

    def ReadRangeSet(self, ranges):
        return [self.data[s * self.blocksize:e * self.blocksize] for (s, e) in ranges]

    def TotalSha1(self, include_clobbered_blocks=False):
        if not include_clobbered_blocks:
            ranges = self.care_map.subtract(self.clobbered_blocks)
            return sha1(b''.join(self.ReadRangeSet(ranges))).hexdigest()
        else:
            return sha1(self.data).hexdigest()


class Transfer:
    def __init__(self, tgt_name, src_name, tgt_ranges, src_ranges, style, by_id):
        self.tgt_name = tgt_name
        self.src_name = src_name
        self.tgt_ranges = tgt_ranges
        self.src_ranges = src_ranges
        self.style = style
        self.intact = (getattr(tgt_ranges, "monotonic", False) and
                       getattr(src_ranges, "monotonic", False))

        self.goes_before = OrderedDict()
        self.goes_after = OrderedDict()

        self.stash_before = []
        self.use_stash = []

        self.id = len(by_id)
        by_id.append(self)

    def NetStashChange(self):
        return (sum(sr.size() for (_, sr) in self.stash_before) -
                sum(sr.size() for (_, sr) in self.use_stash))

    def ConvertToNew(self):
        assert self.style != "new"
        self.use_stash = []
        self.style = "new"
        self.src_ranges = RangeSet()

    def __str__(self):
        return f"{self.id}: <{self.src_ranges} {self.style} to {self.tgt_ranges}>"


@total_ordering
class HeapItem:
    def __init__(self, item):
        self.item = item
        self.score = -item.score

    def clear(self):
        self.item = None

    def __bool__(self):
        return self.item is None

    def __eq__(self, other):
        return self.score == other.score

    def __le__(self, other):
        return self.score <= other.score


class BlockImageDiff:
    def __init__(self, tgt, src=None, version=4, threads=None, disable_imgdiff=False):
        if threads is None:
            threads = max(1, os.cpu_count() // 2)
        self.threads = threads
        self.version = version
        self.transfers = []
        self.src_basenames = {}
        self.src_numpatterns = {}
        self._max_stashed_size = 0
        self.touched_src_ranges = RangeSet()
        self.touched_src_sha1 = None
        self.disable_imgdiff = disable_imgdiff

        assert version in (1, 2, 3, 4)

        self.tgt = tgt
        self.src = src if src else EmptyImage()

        assert tgt.blocksize == 4096
        assert src.blocksize == 4096

        self.AssertPartition(src.care_map, src.file_map.values())
        self.AssertPartition(tgt.care_map, tgt.file_map.values())

    @property
    def max_stashed_size(self):
        return self._max_stashed_size

    def Compute(self, prefix):
        self.AbbreviateSourceNames()
        self.FindTransfers()
        self.GenerateDigraph()
        self.FindVertexSequence()
        
        if self.version == 1:
            self.RemoveBackwardEdges()
        else:
            self.ReverseBackwardEdges()
            self.ImproveVertexSequence()

        if self.version >= 2 and Settings.cache_size is not None:
            self.ReviseStashSize()

        self.AssertSequenceGood()
        self.ComputePatches(prefix)
        self.WriteTransfers(prefix)

    @staticmethod
    def HashBlocks(source, ranges):
        data = source.ReadRangeSet(ranges)
        return sha1(b''.join(data)).hexdigest()

    def WriteTransfers(self, prefix):
        def WriteTransfersZero(out, to_zero):
            zero_blocks_limit = 1024
            total = 0
            while to_zero.size() > 0:
                zero_blocks = to_zero.first(zero_blocks_limit)
                out.append(f"zero {zero_blocks.to_string_raw()}\n")
                total += zero_blocks.size()
                to_zero = to_zero.subtract(zero_blocks)
            return total

        out = []
        total = 0

        stashes = {}
        stashed_blocks = 0
        max_stashed_blocks = 0

        free_stash_ids = []
        next_stash_id = 0

        for xf in self.transfers:
            if self.version < 2:
                assert not xf.stash_before
                assert not xf.use_stash

            for s, sr in xf.stash_before:
                assert s not in stashes
                if free_stash_ids:
                    sid = heappop(free_stash_ids)
                else:
                    sid = next_stash_id
                    next_stash_id += 1
                stashes[s] = sid
                if self.version == 2:
                    stashed_blocks += sr.size()
                    out.append(f"stash {sid:d} {sr.to_string_raw()}\n")
                else:
                    sh = self.HashBlocks(self.src, sr)
                    if sh in stashes:
                        stashes[sh] += 1
                    else:
                        stashes[sh] = 1
                        stashed_blocks += sr.size()
                        self.touched_src_ranges = self.touched_src_ranges.union(sr)
                        out.append(f"stash {sh} {sr.to_string_raw()}\n")

            max_stashed_blocks = max(max_stashed_blocks, stashed_blocks)

            free_string = []
            free_size = 0

            if self.version == 1:
                src_str = xf.src_ranges.to_string_raw() if xf.src_ranges.size() > 0 else ""
            elif self.version >= 2:
                size = xf.src_ranges.size()
                src_str = [str(size)]

                unstashed_src_ranges = xf.src_ranges
                mapped_stashes = []
                for s, sr in xf.use_stash:
                    sid = stashes.pop(s)
                    unstashed_src_ranges = unstashed_src_ranges.subtract(sr)
                    sh = self.HashBlocks(self.src, sr)
                    sr = xf.src_ranges.map_within(sr)
                    mapped_stashes.append(sr)
                    if self.version == 2:
                        src_str.append(f"{sid:d}:{sr.to_string_raw()}")
                        free_string.append(f"free {sid:d}\n")
                        free_size += sr.size()
                    else:
                        assert sh in stashes
                        src_str.append(f"{sh}:{sr.to_string_raw()}")
                        stashes[sh] -= 1
                        if stashes[sh] == 0:
                            free_size += sr.size()
                            free_string.append(f"free {sh}\n")
                            stashes.pop(sh)
                    heappush(free_stash_ids, sid)

                if unstashed_src_ranges.size() > 0:
                    src_str.insert(1, unstashed_src_ranges.to_string_raw())
                    if xf.use_stash:
                        mapped_unstashed = xf.src_ranges.map_within(unstashed_src_ranges)
                        src_str.insert(2, mapped_unstashed.to_string_raw())
                        mapped_stashes.append(mapped_unstashed)
                        self.AssertPartition(RangeSet(data=(0, size)), mapped_stashes)
                else:
                    src_str.insert(1, "-")
                    self.AssertPartition(RangeSet(data=(0, size)), mapped_stashes)

                src_str = " ".join(src_str)

            tgt_size = xf.tgt_ranges.size()

            if xf.style == "new":
                assert xf.tgt_ranges
                out.append(f"{xf.style} {xf.tgt_ranges.to_string_raw()}\n")
                total += tgt_size
            elif xf.style == "move":
                assert xf.tgt_ranges
                assert xf.src_ranges.size() == tgt_size
                if xf.src_ranges != xf.tgt_ranges:
                    if self.version == 1:
                        out.append(f"{xf.style} {xf.src_ranges.to_string_raw()} {xf.tgt_ranges.to_string_raw()}\n")
                    elif self.version == 2:
                        out.append(f"{xf.style} {xf.tgt_ranges.to_string_raw()} {src_str}\n")
                    elif self.version >= 3:
                        if xf.src_ranges.overlaps(xf.tgt_ranges):
                            temp_stash_usage = stashed_blocks + xf.src_ranges.size()
                            max_stashed_blocks = max(max_stashed_blocks, temp_stash_usage)

                        self.touched_src_ranges = self.touched_src_ranges.union(xf.src_ranges)
                        out.append(f"{xf.style} {self.HashBlocks(self.tgt, xf.tgt_ranges)} {xf.tgt_ranges.to_string_raw()} {src_str}\n")
                    total += tgt_size
            elif xf.style in ("bsdiff", "imgdiff"):
                assert xf.tgt_ranges
                assert xf.src_ranges
                if self.version == 1:
                    out.append(f"{xf.style} {xf.patch_start:d} {xf.patch_len:d} {xf.src_ranges.to_string_raw()} {xf.tgt_ranges.to_string_raw()}\n")
                elif self.version == 2:
                    out.append(f"{xf.style} {xf.patch_start:d} {xf.patch_len:d} {xf.tgt_ranges.to_string_raw()} {src_str}\n")
                elif self.version >= 3:
                    if xf.src_ranges.overlaps(xf.tgt_ranges):
                        temp_stash_usage = stashed_blocks + xf.src_ranges.size()
                        max_stashed_blocks = max(max_stashed_blocks, temp_stash_usage)

                    self.touched_src_ranges = self.touched_src_ranges.union(xf.src_ranges)
                    out.append(f"{xf.style} {xf.patch_start:d} {xf.patch_len:d} {self.HashBlocks(self.src, xf.src_ranges)} {self.HashBlocks(self.tgt, xf.tgt_ranges)} {xf.tgt_ranges.to_string_raw()} {src_str}\n")
                total += tgt_size
            elif xf.style == "zero":
                assert xf.tgt_ranges
                to_zero = xf.tgt_ranges.subtract(xf.src_ranges)
                assert WriteTransfersZero(out, to_zero) == to_zero.size()
                total += to_zero.size()
            else:
                raise ValueError(f"unknown transfer style '{xf.style}'\n")

            if free_string:
                out.append("".join(free_string))
                stashed_blocks -= free_size

            if self.version >= 2 and Settings.cache_size is not None:
                cache_size = Settings.cache_size
                stash_threshold = Settings.stash_threshold
                max_allowed = cache_size * stash_threshold
                assert max_stashed_blocks * self.tgt.blocksize < max_allowed, \
                    f'Stash size {max_stashed_blocks * self.tgt.blocksize:d} exceeds the limit {max_allowed:d}'

        if self.version >= 3:
            self.touched_src_sha1 = self.HashBlocks(self.src, self.touched_src_ranges)

        if self.tgt.extended.size() > 0:
            assert (WriteTransfersZero(out, self.tgt.extended) == self.tgt.extended.size())
            total += self.tgt.extended.size()

        all_tgt = RangeSet(data=(0, self.tgt.total_blocks))
        all_tgt_minus_extended = all_tgt.subtract(self.tgt.extended)
        new_dontcare = all_tgt_minus_extended.subtract(self.tgt.care_map)

        erase_first = new_dontcare.subtract(self.touched_src_ranges)
        if erase_first.size() > 0:
            out.insert(0, f"erase {erase_first.to_string_raw()}\n")

        erase_last = new_dontcare.subtract(erase_first)
        if erase_last.size() > 0:
            out.append(f"erase {erase_last.to_string_raw()}\n")

        out.insert(0, f"{self.version:d}\n")
        out.insert(1, f"{total:d}\n")
        if self.version >= 2:
            out.insert(2, str(next_stash_id) + "\n")
            out.insert(3, str(max_stashed_blocks) + "\n")

        with open(prefix + ".transfer.list", "wb") as f:
            f.writelines(i.encode("UTF-8") for i in out)

        if self.version >= 2:
            self._max_stashed_size = max_stashed_blocks * self.tgt.blocksize
            OPTIONS = Settings
            if OPTIONS.cache_size is not None:
                max_allowed = OPTIONS.cache_size * OPTIONS.stash_threshold
                print(f"max stashed blocks: {max_stashed_blocks:d}  limit: {max_allowed:d} bytes")
            else:
                print(f"max stashed blocks: {max_stashed_blocks:d}  limit: <unknown>")

    def ReviseStashSize(self):
        print("Revising stash size...")
        stashes = {}

        for xf in self.transfers:
            for idx, sr in xf.stash_before:
                stashes[idx] = (sr, xf)

            for idx, _ in xf.use_stash:
                stashes[idx] += (xf,)

        cache_size = Settings.cache_size
        stash_threshold = Settings.stash_threshold
        max_allowed = cache_size * stash_threshold / self.tgt.blocksize

        stashed_blocks = 0
        new_blocks = 0

        for xf in self.transfers:
            replaced_cmds = []

            for idx, sr in xf.stash_before:
                if stashed_blocks + sr.size() > max_allowed:
                    use_cmd = stashes[idx][2]
                    replaced_cmds.append(use_cmd)
                    print(f"{sr.size():10d}  {'explicit':>9}  {use_cmd}")
                else:
                    stashed_blocks += sr.size()

            for _, sr in xf.use_stash:
                stashed_blocks -= sr.size()

            if xf.style == "diff" and self.version >= 3:
                assert xf.tgt_ranges and xf.src_ranges
                if xf.src_ranges.overlaps(xf.tgt_ranges):
                    if stashed_blocks + xf.src_ranges.size() > max_allowed:
                        replaced_cmds.append(xf)
                        print(f"{xf.src_ranges.size():10d}  {'implicit':>9}  {xf}")

            for cmd in replaced_cmds:
                for idx, sr in cmd.use_stash:
                    def_cmd = stashes[idx][1]
                    assert (idx, sr) in def_cmd.stash_before
                    def_cmd.stash_before.remove((idx, sr))

                new_blocks += cmd.tgt_ranges.size()
                cmd.ConvertToNew()

        print(f"  Total {new_blocks:d} blocks are packed as new blocks due to insufficient cache size.")

    def ComputePatches(self, prefix):
        print("Computing patches...")
        diff_q = []
        patch_num = 0
        with open(prefix + ".new.dat", "wb") as new_f:
            for xf in self.transfers:
                if xf.style == "zero":
                    continue
                elif xf.style == "new":
                    for piece in self.tgt.ReadRangeSet(xf.tgt_ranges):
                        new_f.write(piece)
                elif xf.style == "diff":
                    src = self.src.ReadRangeSet(xf.src_ranges)
                    tgt = self.tgt.ReadRangeSet(xf.tgt_ranges)

                    src_sha1 = sha1()
                    for p in src:
                        src_sha1.update(p)
                    tgt_sha1 = sha1()
                    tgt_size = sum(len(p) for p in tgt)
                    for p in tgt:
                        tgt_sha1.update(p)

                    if src_sha1.digest() == tgt_sha1.digest():
                        xf.style = "move"
                    else:
                        imgdiff = (not self.disable_imgdiff and xf.intact and
                                   xf.tgt_name.split(".")[-1].lower() in ("apk", "jar", "zip"))
                        xf.style = "imgdiff" if imgdiff else "bsdiff"
                        diff_q.append((tgt_size, src, tgt, xf, patch_num))
                        patch_num += 1

        if diff_q:
            print(f"Computing patches (using {self.threads:d} threads)..." if self.threads > 1 else "Computing patches...")
            diff_q.sort()

            patches = [None] * patch_num
            lock = Lock()

            def diff_worker():
                while True:
                    with lock:
                        if not diff_q:
                            return
                        tgt_size, src, tgt, xf, patchnum = diff_q.pop()
                    patch = compute_patch(src, tgt, imgdiff=(xf.style == "imgdiff"))
                    size = len(patch)
                    with lock:
                        patches[patchnum] = (patch, xf)
                        print(f"{size:10d} {tgt_size:10d} ({size * 100.0 / tgt_size:6.2f}%) {xf.style:>7} {xf.tgt_name if xf.tgt_name == xf.src_name else (xf.tgt_name + ' (from ' + xf.src_name + ')')}")

            threads = [Thread(target=diff_worker) for _ in range(self.threads)]
            for th in threads:
                th.start()
            while threads:
                threads.pop().join()
        else:
            patches = []

        p = 0
        with open(prefix + ".patch.dat", "wb") as patch_f:
            for patch, xf in patches:
                xf.patch_start = p
                xf.patch_len = len(patch)
                patch_f.write(patch)
                p += len(patch)

    def AssertSequenceGood(self):
        touched = [0] * self.tgt.total_blocks

        for xf in self.transfers:
            x = xf.src_ranges
            if self.version >= 2:
                for _, sr in xf.use_stash:
                    x = x.subtract(sr)

            for s, e in x:
                for i in range(s, min(e, self.tgt.total_blocks)):
                    assert touched[i] == 0

            for s, e in xf.tgt_ranges:
                for i in range(s, e):
                    assert touched[i] == 0
                    touched[i] = 1

        for s, e in self.tgt.care_map:
            for i in range(s, e):
                assert touched[i] == 1

    def ImproveVertexSequence(self):
        print("Improving vertex order...")

        for xf in self.transfers:
            xf.incoming = xf.goes_after.copy()
            xf.outgoing = xf.goes_before.copy()
            xf.score = sum(xf.outgoing.values()) - sum(xf.incoming.values())

        G = OrderedDict()
        for xf in self.transfers:
            G[xf] = None
        s1 = deque()
        s2 = deque()

        heap = []
        for xf in self.transfers:
            xf.heap_item = HeapItem(xf)
            heap.append(xf.heap_item)
        heapify(heap)

        sinks = {u for u in G if not u.outgoing}
        sources = {u for u in G if not u.incoming}

        def adjust_score(iu, delta):
            iu.score += delta
            iu.heap_item.clear()
            iu.heap_item = HeapItem(iu)
            heappush(heap, iu.heap_item)

        while G:
            while sinks:
                new_sinks = set()
                for u in sinks:
                    if u not in G:
                        continue
                    s2.appendleft(u)
                    del G[u]
                    for iu in u.incoming:
                        adjust_score(iu, -iu.outgoing.pop(u))
                        if not iu.outgoing:
                            new_sinks.add(iu)
                sinks = new_sinks

            while sources:
                new_sources = set()
                for u in sources:
                    if u not in G:
                        continue
                    s1.append(u)
                    del G[u]
                    for iu in u.outgoing:
                        adjust_score(iu, +iu.incoming.pop(u))
                        if not iu.incoming:
                            new_sources.add(iu)
                sources = new_sources

            if not G:
                break

            while True:
                u = heappop(heap)
                if u and u.item in G:
                    u = u.item
                    break

            s1.append(u)
            del G[u]
            for iu in u.outgoing:
                adjust_score(iu, +iu.incoming.pop(u))
                if not iu.incoming:
                    sources.add(iu)

            for iu in u.incoming:
                adjust_score(iu, -iu.outgoing.pop(u))
                if not iu.outgoing:
                    sinks.add(iu)

        new_transfers = []
        for x in chain(s1, s2):
            x.order = len(new_transfers)
            new_transfers.append(x)
            del x.incoming
            del x.outgoing

        self.transfers = new_transfers

    def RemoveBackwardEdges(self):
        print("Removing backward edges...")
        in_order = 0
        out_of_order = 0
        lost_source = 0

        for xf in self.transfers:
            size = xf.src_ranges.size()
            for u in xf.goes_before:
                if xf.order < u.order:
                    in_order += 1
                else:
                    out_of_order += 1
                    assert xf.src_ranges.overlaps(u.tgt_ranges)
                    xf.src_ranges = xf.src_ranges.subtract(u.tgt_ranges)
                    xf.intact = False

            if xf.style == "diff" and not xf.src_ranges:
                xf.style = "new"

            lost = size - xf.src_ranges.size()
            lost_source += lost

        print(f"  {out_of_order:d}/{in_order + out_of_order:d} dependencies were violated; {lost_source:d} source blocks removed.")

    def ReverseBackwardEdges(self):
        print("Reversing backward edges...")
        in_order = 0
        out_of_order = 0
        stashes = 0
        stash_size = 0

        for xf in self.transfers:
            for u in xf.goes_before.copy():
                if xf.order < u.order:
                    in_order += 1
                else:
                    out_of_order += 1
                    overlap = xf.src_ranges.intersect(u.tgt_ranges)
                    assert overlap
                    u.stash_before.append((stashes, overlap))
                    xf.use_stash.append((stashes, overlap))
                    stashes += 1
                    stash_size += overlap.size()
                    del xf.goes_before[u]
                    del u.goes_after[xf]
                    xf.goes_after[u] = None
                    u.goes_before[xf] = None

        print(f"  {out_of_order:d}/{in_order + out_of_order:d} dependencies were violated; {stash_size:d} source blocks stashed.")

    def FindVertexSequence(self):
        print("Finding vertex sequence...")

        for xf in self.transfers:
            xf.incoming = xf.goes_after.copy()
            xf.outgoing = xf.goes_before.copy()
            xf.score = sum(xf.outgoing.values()) - sum(xf.incoming.values())

        G = OrderedDict()
        for xf in self.transfers:
            G[xf] = None
        s1 = deque()
        s2 = deque()

        heap = []
        for xf in self.transfers:
            xf.heap_item = HeapItem(xf)
            heap.append(xf.heap_item)
        heapify(heap)

        sinks = {u for u in G if not u.outgoing}
        sources = {u for u in G if not u.incoming}

        def adjust_score(iu, delta):
            iu.score += delta
            iu.heap_item.clear()
            iu.heap_item = HeapItem(iu)
            heappush(heap, iu.heap_item)

        while G:
            while sinks:
                new_sinks = set()
                for u in sinks:
                    if u not in G:
                        continue
                    s2.appendleft(u)
                    del G[u]
                    for iu in u.incoming:
                        adjust_score(iu, -iu.outgoing.pop(u))
                        if not iu.outgoing:
                            new_sinks.add(iu)
                sinks = new_sinks

            while sources:
                new_sources = set()
                for u in sources:
                    if u not in G:
                        continue
                    s1.append(u)
                    del G[u]
                    for iu in u.outgoing:
                        adjust_score(iu, +iu.incoming.pop(u))
                        if not iu.incoming:
                            new_sources.add(iu)
                sources = new_sources

            if not G:
                break

            while True:
                u = heappop(heap)
                if u and u.item in G:
                    u = u.item
                    break

            s1.append(u)
            del G[u]
            for iu in u.outgoing:
                adjust_score(iu, +iu.incoming.pop(u))
                if not iu.incoming:
                    sources.add(iu)

            for iu in u.incoming:
                adjust_score(iu, -iu.outgoing.pop(u))
                if not iu.outgoing:
                    sinks.add(iu)

        new_transfers = []
        for x in chain(s1, s2):
            x.order = len(new_transfers)
            new_transfers.append(x)
            del x.incoming
            del x.outgoing

        self.transfers = new_transfers

    def GenerateDigraph(self):
        print("Generating digraph...")
        source_ranges = []
        for b in self.transfers:
            for s, e in b.src_ranges:
                if e > len(source_ranges):
                    source_ranges.extend([None] * (e - len(source_ranges)))
                for i in range(s, e):
                    if source_ranges[i] is None:
                        source_ranges[i] = b
                    else:
                        if not isinstance(source_ranges[i], set):
                            source_ranges[i] = {source_ranges[i]}
                        source_ranges[i].add(b)

        for a in self.transfers:
            intersections = set()
            for s, e in a.tgt_ranges:
                for i in range(s, e):
                    if i >= len(source_ranges):
                        break
                    b = source_ranges[i]
                    if b is not None:
                        if isinstance(b, set):
                            intersections.update(b)
                        else:
                            intersections.add(b)

            for b in intersections:
                if a is b:
                    continue
                i = a.tgt_ranges.intersect(b.src_ranges)
                if i:
                    size = 0 if b.src_name == "__ZERO" else i.size()
                    b.goes_before[a] = size
                    a.goes_after[b] = size

    def FindTransfers(self):
        """Parse the file_map to generate all the transfers."""

        def AddTransfer(tgt_name, src_name, tgt_ranges, src_ranges, style, by_id, split=False):
            if style != "diff" or not split:
                Transfer(tgt_name, src_name, tgt_ranges, src_ranges, style, by_id)
                return

            pieces = 0
            cache_size = Settings.cache_size
            split_threshold = 0.125
            max_blocks_per_transfer = int(cache_size * split_threshold / self.tgt.blocksize)

            if (tgt_ranges.size() <= max_blocks_per_transfer and
                    src_ranges.size() <= max_blocks_per_transfer):
                Transfer(tgt_name, src_name, tgt_ranges, src_ranges, style, by_id)
                return

            while (tgt_ranges.size() > max_blocks_per_transfer and
                   src_ranges.size() > max_blocks_per_transfer):
                tgt_split_name = f"{tgt_name}-{pieces:d}"
                src_split_name = f"{src_name}-{pieces:d}"
                tgt_first = tgt_ranges.first(max_blocks_per_transfer)
                src_first = src_ranges.first(max_blocks_per_transfer)

                Transfer(tgt_split_name, src_split_name, tgt_first, src_first, style, by_id)
                tgt_ranges = tgt_ranges.subtract(tgt_first)
                src_ranges = src_ranges.subtract(src_first)
                pieces += 1

            if tgt_ranges.size() or src_ranges.size():
                assert tgt_ranges.size() and src_ranges.size()
                tgt_split_name = f"{tgt_name}-{pieces:d}"
                src_split_name = f"{src_name}-{pieces:d}"
                Transfer(tgt_split_name, src_split_name, tgt_ranges, src_ranges, style, by_id)

        empty = RangeSet()
        for tgt_fn, tgt_ranges in self.tgt.file_map.items():
            if tgt_fn == "__ZERO":
                src_ranges = self.src.file_map.get("__ZERO", empty)
                AddTransfer(tgt_fn, "__ZERO", tgt_ranges, src_ranges, "zero", self.transfers)
                continue

            elif tgt_fn == "__COPY":
                AddTransfer(tgt_fn, None, tgt_ranges, empty, "new", self.transfers)
                continue

            elif tgt_fn in self.src.file_map:
                AddTransfer(tgt_fn, tgt_fn, tgt_ranges, self.src.file_map[tgt_fn], "diff", self.transfers, self.version >= 3)
                continue

            b = os.path.basename(tgt_fn)
            if b in self.src_basenames:
                src_fn = self.src_basenames[b]
                AddTransfer(tgt_fn, src_fn, tgt_ranges, self.src.file_map[src_fn], "diff", self.transfers, self.version >= 3)
                continue

            b = sub("[0-9]+", "#", b)
            if b in self.src_numpatterns:
                src_fn = self.src_numpatterns[b]
                AddTransfer(tgt_fn, src_fn, tgt_ranges, self.src.file_map[src_fn], "diff", self.transfers, self.version >= 3)
                continue

            AddTransfer(tgt_fn, None, tgt_ranges, empty, "new", self.transfers)

    def AbbreviateSourceNames(self):
        for k in self.src.file_map.keys():
            b = os.path.basename(k)
            self.src_basenames[b] = k
            b = sub("[0-9]+", "#", b)
            self.src_numpatterns[b] = k

    @staticmethod
    def AssertPartition(total, seq):
        so_far = RangeSet()
        for i in seq:
            assert not so_far.overlaps(i)
            so_far = so_far.union(i)
        assert so_far == total
