import ffmpeg
import numpy as np
import h5py

def load_from_h5(filename):
    """Load Y, Cb, Cr macroblock data from HDF5 file"""
    with h5py.File(filename, 'r') as f:
        Y_macroblocks = np.array(f['Y_macroblocks'])
        Cb_macroblocks = np.array(f['Cb_macroblocks'])
        Cr_macroblocks = np.array(f['Cr_macroblocks'])

    # print("Loaded data:")
    # print(f"Y macroblocks array shape: {Y_macroblocks.shape}")
    # print(f"Cb macroblocks array shape: {Cb_macroblocks.shape}")
    # print(f"Cr macroblocks array shape: {Cr_macroblocks.shape}")

    # # Output first macroblock data
    # print("First Y macroblock:")
    # print(Y_macroblocks)
    # print("First Cb macroblock:")
    # print(Cb_macroblocks)
    # print("First Cr macroblock:")
    # print(Cr_macroblocks)

    return Y_macroblocks, Cb_macroblocks, Cr_macroblocks

if __name__ == "__main__":
    # Example call
    filename = 'output_video_data.h5'  # Your HDF5 file path
    Y_macroblocks, Cb_macroblocks, Cr_macroblocks = load_from_h5(filename)
