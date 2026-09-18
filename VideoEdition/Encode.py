import ffmpeg
import numpy as np
import h5py

MACROBLOCK_SIZE = 16  # Macroblock size 16x16


def read_from_h5(filename):
    """ Read Y, Cb, Cr macroblock data from HDF5 file """
    with h5py.File(filename, 'r') as f:
        Y_macroblocks = np.array(f['Y_macroblocks'])
        Cb_macroblocks = np.array(f['Cb_macroblocks'])
        Cr_macroblocks = np.array(f['Cr_macroblocks'])

    print(f"Data read: Y macroblocks {Y_macroblocks.shape}, Cb macroblocks {Cb_macroblocks.shape}, Cr macroblocks {Cr_macroblocks.shape}")
    return Y_macroblocks, Cb_macroblocks, Cr_macroblocks


def reconstruct_frame(Y_macroblocks, Cb_macroblocks, Cr_macroblocks, width, height):
    """ Reconstruct macroblock data back to YUV frame """
    macroblocks_x = width // MACROBLOCK_SIZE
    macroblocks_y = height // MACROBLOCK_SIZE

    # Initialize Y, Cb, Cr
    Y = np.zeros((height, width), dtype=np.uint8)
    Cb = np.zeros((height // 2, width // 2), dtype=np.uint8)
    Cr = np.zeros((height // 2, width // 2), dtype=np.uint8)

    index = 0
    for mb_y in range(macroblocks_y):
        for mb_x in range(macroblocks_x):
            start_x, start_y = mb_x * MACROBLOCK_SIZE, mb_y * MACROBLOCK_SIZE

            # Restore Y macroblock
            Y[start_y:start_y + MACROBLOCK_SIZE, start_x:start_x + MACROBLOCK_SIZE] = Y_macroblocks[index]

            # Restore Cb, Cr (since they are 8x8)
            Cb[start_y // 2:(start_y + MACROBLOCK_SIZE) // 2, start_x // 2:(start_x + MACROBLOCK_SIZE) // 2] = Cb_macroblocks[index]
            Cr[start_y // 2:(start_y + MACROBLOCK_SIZE) // 2, start_x // 2:(start_x + MACROBLOCK_SIZE) // 2] = Cr_macroblocks[index]

            index += 1

    return Y, Cb, Cr


def save_video_from_yuv(output_filename, Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, width, height, fps):
    """ Re-encode YUV data back to video """

    process = (
        ffmpeg
        .input('pipe:', format='rawvideo', pix_fmt='yuv420p', s=f"{width}x{height}", r=fps)
        .output(output_filename, pix_fmt='yuv420p', vcodec='libx264', crf=18)
        .overwrite_output()
        .run_async(pipe_stdin=True)
    )

    for i in range(len(Y_macroblocks_all)):  # Iterate through all frames
        Y, Cb, Cr = reconstruct_frame(Y_macroblocks_all[i], Cb_macroblocks_all[i], Cr_macroblocks_all[i], width, height)

        # YUV 420P needs to be arranged in order of Y, U, V planes
        raw_frame = np.concatenate([Y.flatten(), Cb.flatten(), Cr.flatten()])
        process.stdin.write(raw_frame.tobytes())

    process.stdin.close()
    process.wait()
    print(f"Video saved to {output_filename}")


def save_video_from_yuv_noloss(output_filename, Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, width, height, fps):
    """ Re-encode YUV data to lossless video (H.264) """

    process = (
        ffmpeg
        .input('pipe:', format='rawvideo', pix_fmt='yuv420p', s=f"{width}x{height}", r=fps)
        .output(
            output_filename,
            pix_fmt='yuv420p',
            vcodec='libx264',
            preset='veryslow',                 # Better compression efficiency (optional)
            **{'crf': '0', 'x264-params': 'qp=0:lossless=1'}  # Key: lossless encoding settings
        )
        .overwrite_output()
        .global_args('-loglevel', 'error')
        .run_async(pipe_stdin=True)
    )

    for i in range(len(Y_macroblocks_all)):
        Y, Cb, Cr = reconstruct_frame(Y_macroblocks_all[i], Cb_macroblocks_all[i], Cr_macroblocks_all[i], width, height)

        raw_frame = np.concatenate([Y.flatten(), Cb.flatten(), Cr.flatten()])
        process.stdin.write(raw_frame.tobytes())

    process.stdin.close()
    process.wait()
    print(f"Edited video losslessly saved to: {output_filename}")

if __name__ == '__main__':
    # Read data from HDF5
    h5_filename = "output_video_data.h5"
    Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all = read_from_h5(h5_filename)

    # Set video parameters (should match original video)
    width = 3840  # 4K width
    height = 2160  # 4K height
    fps = 30  # Frame rate

    # Generate video
    save_video_from_yuv("reconstructed_video.mp4", Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, width, height, fps)
