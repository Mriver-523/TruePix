import argparse
import Frame_Block_Extraction
import Gray
import Encode
import Inv
import Crop
import Mask
import Read
import subprocess

def main():

    parser = argparse.ArgumentParser(
        description="Video editing tool: supports grayscale, color inversion, mask, cropping, etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--input', required=True, help="Input video file path")
    parser.add_argument('--output', default='output.mp4', help="Output video file path, default: output.mp4")
    parser.add_argument('--input_data', default='input.txt', help="File path to save input video YCbCr data, default: input.txt")
    parser.add_argument('--output_data', default='output.txt', help="File path to save output video YCbCr data, default: output.txt")
    parser.add_argument('--gray', action='store_true', help="Grayscale processing")
    parser.add_argument('--invert', action='store_true', help="Color inversion")
    parser.add_argument('--mask', action='store_true', help="Apply mask (mosaic) effect")
    parser.add_argument('--crop', nargs=4, type=float, metavar=('x_start', 'x_end', 'y_start', 'y_end'),
                        help="Crop image area, using 0~1 range coordinates, e.g., 0.2 0.8 0.2 0.8")

    args = parser.parse_args()
    
    # Get video information
    width, height, fps = Frame_Block_Extraction.get_video_info(args.input)

    print(f"Video information: {width}x{height} @ {fps}fps")

    print("Video decoding in progress...")
    # Macroblock extraction
    #Y, Cb, Cr = Frame_Block_Extraction.process_video_and_save_to_h5(args.input, args.input_h5)
    Y, Cb, Cr =Frame_Block_Extraction.process_video_and_save_to_txt(args.input, args.input_data)
    print("Video decoding completed")

    # Grayscale
    if args.gray:
        Cb, Cr = Gray.grayscale(Cb, Cr)

    # Inversion
    if args.invert:
        Y, Cb, Cr = Inv.invert(Y, Cb, Cr)

    # Mask (mosaic)
    if args.mask:
        Y, Cb, Cr = Mask.mosaic(Y, Cb, Cr)

    orig_width = width
    orig_height = height
    # Cropping
    if args.crop:
        x_start, x_end, y_start, y_end = args.crop
        Y, Cb, Cr,b= Crop.crop(Y, Cb, Cr, x_start, x_end, y_start, y_end, width, height,args.input_data)
        # #Modified video dimensions
        W_block=int(width/16)
        H_block=int(height/16)

        width=int(W_block*x_end)*16-int(W_block*x_start)*16
        height=int(H_block*y_end)*16-int(H_block*y_start)*16


    Frame_Block_Extraction.save_to_txt(Y,Cb,Cr,args.output_data)
    # Save video
    if args.crop:
        Y, Cb, Cr=Crop.crop_encode(Y, Cb, Cr, b, orig_width, orig_height)
    print("Video encoding in progress...")
    Encode.save_video_from_yuv_noloss(args.output,Y,Cb,Cr,width,height,fps)
    
    print(f"Original video first frame data saved to: {args.input_data}")
    print(f"Edited video first frame data saved to: {args.output_data}")
    #print(f"Edited video saved to: {args.output}")
if __name__ == '__main__':
    main()
