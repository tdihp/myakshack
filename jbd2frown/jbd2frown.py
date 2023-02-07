#!/usr/bin/env python3
"""
This file reads its own source code lines, and writes a fragmented file.

Let's see how fragements of ext4 on Azure dance!
"""


import sys
import inspect
import hashlib
import itertools as it
import random
import logging
import os
import re
from subprocess import run
from pathlib import Path

logger = logging.getLogger('repro')


def block_samples(blksize, blkpoolsize=128):
    """generate sample block sizes"""
    # use src code of this file to generate content, random enough for me ;)
    lines, _ = inspect.getsourcelines(sys.modules[__name__])
    h = hashlib.new('md5')
    pieces = []
    for line in lines:
        h.update(line.encode())
        pieces.append(h.hexdigest().encode())

    piece_size = h.digest_size * 2  # 2 hex digits for 1 raw byte
    blk_pieces = (blksize // piece_size) + (1 if (blksize % piece_size) else 0)
    blks = [b''.join(random.choices(pieces, k=blk_pieces))[:blksize] 
            for i in range(blkpoolsize)]
    return it.cycle(blks)


def make_fragmented_file(fname, fsize, blksize):
    fpath = Path(fname)
    logger.info('creating file with fname=%s, fsize=%s, blksize=%s',
                fname, fsize, blksize)
    with fpath.open('wb', buffering=False) as f:
        fd = f.fileno()
        logger.info('truncating to double size')
        os.ftruncate(fd, fsize * 2)
        logger.info('writing combs')
        for offset, blk in zip(range(0, fsize, blksize * 2),
                               block_samples(blksize)):
            os.lseek(fd, offset, os.SEEK_SET)
            f.write(blk)
        logger.info('fdatasync')
        os.fdatasync(fd)

    logger.info('digging holes')
    # dig right to left to avoid messing with original offsets.
    for offset in reversed(range(blksize, fsize, blksize * 2)):
        logger.debug('punching holes at %d', offset)
        run(['fallocate', '-x', '-o', str(offset), '-l', str(blksize), str(fpath)], check=True)
    logger.info('file %s prepared', fpath)


def po2int(txt):
    """allow K, M, G suffixed sizes"""
    m = re.match('^([1-9]\d*)([KMG]?)$', txt)
    if not m:
        raise ValueError('invalid po2 size %s' % txt)

    SCALEMAP = {'K': 1024, 'M': 1024 * 1024, 'G': 1024 * 1024 * 1024}
    base, scale = m.groups()
    return int(base) * SCALEMAP[scale]


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog = 'jbd2frown',
        description = 'Generate a fragmented file on Linux with fallocate '
                      'file for testing jbd2 tight loop')
    parser.add_argument('-v', '--verbose', action='store_const',
                        default=logging.INFO, const=logging.DEBUG)
    parser.add_argument('-b', '--block-size', default='4K', type=po2int,
                        help='block size in bytes, default to 4096')
    parser.add_argument('-s', '--total-size', default='4M', type=po2int,
                        help='total file size, default to 4M')
    parser.add_argument('path', help='output file path', type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=args.verbose, format='%(asctime)s %(message)s')
    make_fragmented_file(args.path, args.total_size, args.block_size)


if __name__ == '__main__':
    main()
    # make_fragmented_file('foobar.dat', 128*1024*1024, 4096)
    # comb('foobar.dat', 128*1024*1024, 4096, 8)
