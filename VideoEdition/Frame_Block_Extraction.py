import ffmpeg
import numpy as np
import h5py

MACROBLOCK_SIZE = 16  # Macroblock size 16x16

# Get video information
def get_video_info(video_path):
    """
    Get video width, height and frame rate (FPS, as integer).

    Parameters:
      video_path: Video file path

    Returns:
      width: Video width
      height: Video height
      fps: Frame rate (integer)
    """
    probe = ffmpeg.probe(
        video_path,
        v='error',
        select_streams='v:0',
        show_entries='stream=width,height,r_frame_rate'
    )
    stream = probe['streams'][0]
    width = stream.get('width')
    height = stream.get('height')
    r_frame_rate = stream.get('r_frame_rate')
    num, den = map(float, r_frame_rate.split('/'))
    fps = int(round(num / den))  # Convert to integer
    return width, height, fps


# Decode video
def decode_video_to_yuv(video_path, width, height):
    """ Use FFmpeg to decode video and return YUV420P data """

    # Use FFmpeg to decode video and convert to YUV420P format raw data
    process = (
        ffmpeg
        .input(video_path)
        .output('pipe:', format='rawvideo', pix_fmt='yuv420p', s=f"{width}x{height}")
        .global_args('-loglevel', 'error')
        .run_async(pipe_stdout=True)
    )

    frame_size = width * height * 3 // 2  # YUV420P requires 1.5 times Y plane size

    while True:
        raw_frame = process.stdout.read(frame_size)
        if not raw_frame:
            break  # Reading completed

        # Parse YUV420P data
        Y = np.frombuffer(raw_frame[0:width * height], dtype=np.uint8).reshape((height, width))
        Cb = np.frombuffer(raw_frame[width * height:width * height + (width // 2) * (height // 2)],
                           dtype=np.uint8).reshape((height // 2, width // 2))
        Cr = np.frombuffer(raw_frame[width * height + (width // 2) * (height // 2):], dtype=np.uint8).reshape(
            (height // 2, width // 2))

        yield Y, Cb, Cr

    process.wait()

# Macroblock partitioning
def process_macroblocks(Y, Cb, Cr, width, height):
    """ Partition Y, Cb, Cr data into 16x16 macroblocks and return """

    macroblocks_x = width // MACROBLOCK_SIZE
    macroblocks_y = height // MACROBLOCK_SIZE

    Y_macroblocks = []
    Cb_macroblocks = []
    Cr_macroblocks = []

    # Partition Y, Cb, Cr by macroblock size
    for mb_y in range(macroblocks_y):
        for mb_x in range(macroblocks_x):
            start_x, start_y = mb_x * MACROBLOCK_SIZE, mb_y * MACROBLOCK_SIZE

            # Extract 16x16 macroblock for Y component
            Y_block = Y[start_y:start_y + MACROBLOCK_SIZE, start_x:start_x + MACROBLOCK_SIZE]
            # Extract 8x8 macroblock for Cb component (note: Cb and Cr resolution is half of Y)
            Cb_block = Cb[start_y // 2:(start_y + MACROBLOCK_SIZE) // 2, start_x // 2:(start_x + MACROBLOCK_SIZE) // 2]
            Cr_block = Cr[start_y // 2:(start_y + MACROBLOCK_SIZE) // 2, start_x // 2:(start_x + MACROBLOCK_SIZE) // 2]

            # Save Y, Cb, Cr macroblocks separately
            Y_macroblocks.append(Y_block)
            Cb_macroblocks.append(Cb_block)
            Cr_macroblocks.append(Cr_block)

    # Return Y, Cb, Cr macroblocks as NumPy arrays
    return np.array(Y_macroblocks), np.array(Cb_macroblocks), np.array(Cr_macroblocks)

# Decode and return YUV
def process_video_and_return_yuv(video_path):
    """ Decode video and return Y, Cb, Cr macroblock arrays """

    # Automatically get video resolution
    probe = ffmpeg.probe(video_path, v='error', select_streams='v:0', show_entries='stream=width,height')
    width = probe['streams'][0]['width']
    height = probe['streams'][0]['height']
    #print(f"Video resolution: {width}x{height}")

    Y_macroblocks_all = []
    Cb_macroblocks_all = []
    Cr_macroblocks_all = []

    # Decode video and process each frame
    for Y, Cb, Cr in decode_video_to_yuv(video_path, width, height):
        # Partition YUV data into macroblocks and save as NumPy arrays
        Y_macroblocks, Cb_macroblocks, Cr_macroblocks = process_macroblocks(Y, Cb, Cr, width, height)

        # Add each frame's Y, Cb, Cr macroblock data to global arrays
        Y_macroblocks_all.append(Y_macroblocks)
        Cb_macroblocks_all.append(Cb_macroblocks)
        Cr_macroblocks_all.append(Cr_macroblocks)

    # Combine all frames' macroblock data into large arrays with shape (frame_count, macroblock_count, 16, 16)
    Y_macroblocks_all = np.array(Y_macroblocks_all)
    Cb_macroblocks_all = np.array(Cb_macroblocks_all)
    Cr_macroblocks_all = np.array(Cr_macroblocks_all)

    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all

# Decode return YUV and synchronously save to .h5 file
def process_video_and_save_to_h5_(video_path,filename):
    """ Save Y, Cb, Cr data to HDF5 file """
    Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all=process_video_and_return_yuv(video_path)
    with h5py.File(filename, 'w') as f:
        f.create_dataset('Y_macroblocks', data=Y_macroblocks_all)
        f.create_dataset('Cb_macroblocks', data=Cb_macroblocks_all)
        f.create_dataset('Cr_macroblocks', data=Cr_macroblocks_all)

    print(f"Video data saved to {filename} file")
    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all

def process_video_and_save_to_h5(video_path,out_filename):
    Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all = process_video_and_return_yuv(video_path)
    '''Save all data'''
    # Y=Y_macroblocks_all.reshape(-1, 16 * 16)
    # Cb=Cb_macroblocks_all.reshape(-1, 8 * 8)
    # Cr=Cr_macroblocks_all.reshape(-1, 8 * 8)

    '''Save only first frame data'''
    Y = Y_macroblocks_all[0].reshape(-1, 16 * 16)
    Cb = Cb_macroblocks_all[0].reshape(-1, 8 * 8)
    Cr = Cr_macroblocks_all[0].reshape(-1, 8 * 8)

    num_blocks = Y.shape[0]  # Number of macroblocks
    merged_macroblocks = np.zeros((num_blocks, 384), dtype=np.uint8)  # Pre-allocate array

    for i in range(num_blocks):
        # Flatten and concatenate
        merged_macroblocks[i] = np.concatenate([
            Y[i].flatten(),
            Cb[i].flatten(),
            Cr[i].flatten()
        ])

    with h5py.File(out_filename, 'w') as f:
        f.create_dataset('merged_macroblocks', data=merged_macroblocks)
    #print(f"Video data saved to {out_filename} file")
    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all

def process_video_and_save_to_txt(video_path, out_filename):
    Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all = process_video_and_return_yuv(video_path)

    '''Save only first frame data'''
    Y = Y_macroblocks_all[0].reshape(-1, 16 * 16)     # Each macroblock flattened to 256 dimensions
    Cb = Cb_macroblocks_all[0].reshape(-1, 8 * 8)     # Each macroblock flattened to 64 dimensions
    Cr = Cr_macroblocks_all[0].reshape(-1, 8 * 8)

    num_blocks = Y.shape[0]
    #print("num_blocks=",num_blocks)

    with open(out_filename, 'w') as f:
        for i in range(num_blocks):
            merged = np.concatenate([Y[i], Cb[i], Cr[i]])
            merged_str = ' '.join(map(str, merged))  # Use space as separator
            f.write(merged_str + '\n')

    #print(f"First frame macroblock data saved as TXT file: {out_filename}")
    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all

def save_to_h5(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, filename):
    """ Save Y, Cb, Cr data to HDF5 file """
    Y = Y_macroblocks_all[0].reshape(-1, 16 * 16)
    Cb = Cb_macroblocks_all[0].reshape(-1, 8 * 8)
    Cr = Cr_macroblocks_all[0].reshape(-1, 8 * 8)
    num_blocks = Y.shape[0]  # Number of macroblocks
    merged_macroblocks = np.zeros((num_blocks, 384), dtype=np.uint8)  # Pre-allocate array

    for i in range(num_blocks):
        # Flatten and concatenate
        merged_macroblocks[i] = np.concatenate([
            Y[i].flatten(),
            Cb[i].flatten(),
            Cr[i].flatten()
        ])
    with h5py.File(filename, 'w') as f:
        f.create_dataset('Y_macroblocks', data=Y_macroblocks_all)
        f.create_dataset('Cb_macroblocks', data=Cb_macroblocks_all)
        f.create_dataset('Cr_macroblocks', data=Cr_macroblocks_all)

    #print(f"Data saved to {filename}")

def save_to_txt(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, filename):
    """ Save Y, Cb, Cr data to HDF5 file """
    Y = Y_macroblocks_all[0].reshape(-1, 16 * 16)
    Cb = Cb_macroblocks_all[0].reshape(-1, 8 * 8)
    Cr = Cr_macroblocks_all[0].reshape(-1, 8 * 8)
    num_blocks = Y.shape[0]  # Number of macroblocks
    merged_macroblocks = np.zeros((num_blocks, 384), dtype=np.uint8)  # Pre-allocate array

    for i in range(num_blocks):
        # Flatten and concatenate
        merged_macroblocks[i] = np.concatenate([
            Y[i].flatten(),
            Cb[i].flatten(),
            Cr[i].flatten()
        ])
    with open(filename, 'w') as f:
        for i in range(num_blocks):
            merged = np.concatenate([Y[i], Cb[i], Cr[i]])
            merged_str = ' '.join(map(str, merged))  # Use space as separator
            f.write(merged_str + '\n')

    #print(f"First frame macroblock data saved as TXT file: {filename}")
    return Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all

    #print(f"Data saved to {filename}")
# Save only first frame
def save_to_h5_first(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, filename):
    """ Save first frame's Y, Cb, Cr data to HDF5 file """

    with h5py.File(filename, 'w') as f:
        f.create_dataset('Y_macroblocks', data=Y_macroblocks_all[0])
        f.create_dataset('Cb_macroblocks', data=Cb_macroblocks_all[0])
        f.create_dataset('Cr_macroblocks', data=Cr_macroblocks_all[0])

    print(f"Data saved to {filename}")



if __name__ == '__main__':
    # Example: Call function to get Y, Cb, Cr macroblock data and save to HDF5 file
    video_path = '../Video/background_720.mp4'  # Video file path
    Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all = process_video_and_return_yuv(video_path)
    print(Y_macroblocks_all[0,0,:,:],Cb_macroblocks_all[0,0,:,:],Cr_macroblocks_all[0,0,:,:])
    print(f"Y macroblock array shape: {Y_macroblocks_all.shape}")
    print(f"Cb macroblock array shape: {Cb_macroblocks_all.shape}")
    print(f"Cr macroblock array shape: {Cr_macroblocks_all.shape}")

    # Save data to HDF5 file
    save_to_h5_first(Y_macroblocks_all, Cb_macroblocks_all, Cr_macroblocks_all, 'test.h5')
