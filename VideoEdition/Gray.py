import ffmpeg
import numpy as np
import h5py
from tqdm import tqdm


def grayscale_macroblock(Cb_block, Cr_block):
    Cb_block[:] = 128
    Cr_block[:] = 128
    return Cb_block, Cr_block


def grayscale(Cb_macroblocks_all, Cr_macroblocks_all):
    num_frames = Cb_macroblocks_all.shape[0]
    num_blocks = Cb_macroblocks_all.shape[1]
    for frame_idx in tqdm(range(num_frames), desc="Processing grayscale", unit="frame"):
        for block_idx in range(num_blocks):
            Cb_macroblocks_all[frame_idx, block_idx], Cr_macroblocks_all[frame_idx, block_idx] = \
                grayscale_macroblock(Cb_macroblocks_all[frame_idx, block_idx],
                                     Cr_macroblocks_all[frame_idx, block_idx])
        #print(f"Completed macroblock grayscale processing for frame {frame_idx}")
    return Cb_macroblocks_all, Cr_macroblocks_all
