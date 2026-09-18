import numpy as np
from tqdm import tqdm


def crop_macroblock_zero(Y_blocks, Cb_blocks, Cr_blocks, b):
    if b == 0:
        return np.array([]), np.array([]), np.array([])
    return Y_blocks, Cb_blocks, Cr_blocks

def crop_macroblock(Y_blocks, Cb_blocks, Cr_blocks, b):
    if b == 0:
        return (
            np.zeros_like(Y_blocks),
            np.zeros_like(Cb_blocks),
            np.zeros_like(Cr_blocks)
        )
    return Y_blocks, Cb_blocks, Cr_blocks

def crop(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, x_start, x_end, y_start, y_end, width, height, filename):
    """
    Crop macroblocks for all frames using relative coordinates (0,1) as units.
    """
    H_blocks = int(height / 16)
    W_blocks = int(width / 16)

    b = np.zeros((H_blocks, W_blocks), dtype=np.uint8)

    # Calculate crop range (cropping at macroblock level)
    x_start_idx = int(x_start * W_blocks)
    x_end_idx = int(x_end * W_blocks)
    y_start_idx = int(y_start * H_blocks)
    y_end_idx = int(y_end * H_blocks)

    b[y_start_idx:y_end_idx, x_start_idx:x_end_idx] = 1
    b_flat = b.flatten()

    num_frames = Y_macroblocks_all.shape[0]
    cropped_Y = []
    cropped_Cb = []
    cropped_Cr = []

    for frame_idx in tqdm(range(num_frames), desc="Cropping", unit="frame"):
        Y_frame = []
        Cb_frame = []
        Cr_frame = []
        for i in range(H_blocks * W_blocks):
            Y_block, Cb_block, Cr_block = crop_macroblock(Y_macroblocks_all[frame_idx][i],
                                                          Cb_macroblocks_all[frame_idx][i],
                                                          Cr_macroblocks_all[frame_idx][i], b_flat[i])
            if Y_block.size == 0:
                continue
            Y_frame.append(Y_block)
            Cb_frame.append(Cb_block)
            Cr_frame.append(Cr_block)

        cropped_Y.append(Y_frame)
        cropped_Cb.append(Cb_frame)
        cropped_Cr.append(Cr_frame)

    with open(filename, "r") as f:
        lines = f.readlines()

    with open(filename, "w") as f:
        for line, new_val in zip(lines, b_flat):
            line = line.strip()
            if line:
                f.write(f"{line} {new_val}\n")

        #print(f"Macroblock cropping completed for frame {frame_idx}")

    return np.array(cropped_Y), np.array(cropped_Cb), np.array(cropped_Cr), b_flat

def crop_encode(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, b_flat, width, height):
    H_blocks = int(height / 16)
    W_blocks = int(width / 16)
    num_frames = Y_macroblocks_all.shape[0]
    cropped_Y = []
    cropped_Cb = []
    cropped_Cr = []

    for frame_idx in range(num_frames):
        Y_frame = []
        Cb_frame = []
        Cr_frame = []
        for i in range(H_blocks * W_blocks):
            Y_block, Cb_block, Cr_block = crop_macroblock_zero(Y_macroblocks_all[frame_idx][i],
                                                               Cb_macroblocks_all[frame_idx][i],
                                                               Cr_macroblocks_all[frame_idx][i], b_flat[i])
            if Y_block.size == 0:
                continue
            Y_frame.append(Y_block)
            Cb_frame.append(Cb_block)
            Cr_frame.append(Cr_block)

        cropped_Y.append(Y_frame)
        cropped_Cb.append(Cb_frame)
        cropped_Cr.append(Cr_frame)
    return np.array(cropped_Y), np.array(cropped_Cb), np.array(cropped_Cr)
