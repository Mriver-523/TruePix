import numpy as np
from tqdm import tqdm

def invert_macroblock(Y_block, Cb_block, Cr_block):
    # Invert operation: Y, Cb, Cr components perform 255 - x pixel by pixel
    Y_block[:] = 255 - Y_block
    Cb_block[:] = 255 - Cb_block
    Cr_block[:] = 255 - Cr_block
    return Y_block, Cb_block, Cr_block

def invert(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all):
    num_frames = Y_macroblocks_all.shape[0]
    num_blocks = Y_macroblocks_all.shape[1]

    for frame_idx in tqdm(range(num_frames), desc="Color inversion in progress", unit="frame"):
        for block_idx in range(num_blocks):
            Y_macroblocks_all[frame_idx, block_idx], \
            Cb_macroblocks_all[frame_idx, block_idx], \
            Cr_macroblocks_all[frame_idx, block_idx] = invert_macroblock(
                Y_macroblocks_all[frame_idx, block_idx],
                Cb_macroblocks_all[frame_idx, block_idx],
                Cr_macroblocks_all[frame_idx, block_idx]
            )

        # print(f"Inversion processing completed for frame {frame_idx}")

    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all
