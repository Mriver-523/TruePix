import numpy as np
from tqdm import tqdm

def mosaic_macroblock(Y_block, Cb_block, Cr_block):
    # Apply mosaic to Y channel
    Y_mosaic = np.copy(Y_block)
    # Get the center pixel value of the current macroblock
    center_value = Y_block[8,8]
    # Fill the entire macroblock area with this center value
    Y_mosaic[:,:] = center_value

    # Apply mosaic to Cb and Cr channels
    Cb_mosaic = np.copy(Cb_block)
    Cr_mosaic = np.copy(Cr_block)

    center_value_Cb = Cb_block[4,4]
    center_value_Cr = Cr_block[4,4]
    # Fill the entire macroblock area with this center value
    Cb_mosaic[:,:] = center_value_Cb
    Cr_mosaic[:,:] = center_value_Cr

    return Y_mosaic, Cb_mosaic, Cr_mosaic


def mosaic(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all):
    """
    Apply mosaic effect to YCbCr macroblock arrays for all frames.
    """
    num_frames = Y_macroblocks_all.shape[0]
    num_blocks = Y_macroblocks_all.shape[1]
    mosaic_Y = []
    mosaic_Cb = []
    mosaic_Cr = []

    # Process macroblocks one by one
    for frame_idx in tqdm(range(num_frames), desc="Mosaic processing", unit="frame"):
        Y_temp = []
        Cb_temp = []
        Cr_temp = []
        for block_idx in range(num_blocks):
            Y_mosaic, Cb_mosaic, Cr_mosaic = mosaic_macroblock(
                Y_macroblocks_all[frame_idx][block_idx],
                Cb_macroblocks_all[frame_idx][block_idx],
                Cr_macroblocks_all[frame_idx][block_idx]
            )
            Y_temp.append(Y_mosaic)
            Cb_temp.append(Cb_mosaic)
            Cr_temp.append(Cr_mosaic)
        mosaic_Y.append(Y_temp)
        mosaic_Cb.append(Cb_temp)
        mosaic_Cr.append(Cr_temp)
        #print(f"Mosaic effect completed for frame {frame_idx}")

    return np.array(mosaic_Y), np.array(mosaic_Cb), np.array(mosaic_Cr)
