def compute_half_third(prime):
    """
    计算 prime 对应的 half 和 third
    half = (prime + 1) // 2  (ceil(prime/2))
    third = 2 * (prime // 3) + 1  (floor(prime/3) 的两倍加1)
    """
    half = (prime + 1) // 2
    third = 2 * (prime // 3) + 1
    return half, third


def verify_with_known_example():
    """用已知的 2**61 - 1 验证计算方法"""
    print("=" * 70)
    print("验证：使用 2**61 - 1 作为参考")
    print("=" * 70)
    
    prime_61 = 2 ** 61 - 1
    half_61, third_61 = compute_half_third(prime_61)
    
    # 已知的正确值
    expected_half = 1152921504606846976
    expected_third = 1537228672809129301
    
    print(f"prime = {prime_61}")
    print(f"half   = {half_61}")
    print(f"期望 half = {expected_half}")
    print(f"half 验证: {'✅ 正确' if half_61 == expected_half else '❌ 错误'}")
    print()
    print(f"third  = {third_61}")
    print(f"期望 third = {expected_third}")
    print(f"third 验证: {'✅ 正确' if third_61 == expected_third else '❌ 错误'}")
    
    # 显示计算细节
    print(f"\n计算细节:")
    print(f"  prime // 3 = {prime_61 // 3}")
    print(f"  2 * (prime // 3) + 1 = {2 * (prime_61 // 3) + 1}")
    print("=" * 70)
    print()


def test_prime_128():
    """测试 2**128 - 159 的计算"""
    print("=" * 70)
    print("计算 prime = 2**128 - 159 的 half 和 third")
    print("=" * 70)
    
    prime = 2 ** 128 - 159
    half, third = compute_half_third(prime)
    
    print(f"prime = {prime}")
    print(f"prime (hex) = 0x{prime:x}")
    print(f"prime 位数 = {prime.bit_length()} bits")
    print()
    print(f"half  = {half}")
    print(f"half (hex) = 0x{half:x}")
    print(f"验证: 2*half == prime+1? {'✅' if 2*half == prime+1 else '❌'}")
    print()
    print(f"third = {third}")
    print(f"third (hex) = 0x{third:x}")
    print(f"验证: (third-1)//2 == prime//3? {'✅' if (third-1)//2 == prime//3 else '❌'}")
    print(f"      third = 2*floor(prime/3) + 1? {'✅' if third == 2*(prime//3)+1 else '❌'}")
    
    # 显示计算细节
    print(f"\n计算细节:")
    print(f"  prime // 3 = {prime // 3}")
    print(f"  2 * (prime // 3) + 1 = {third}")
    print("=" * 70)
    print()


def analyze_different_methods():
    """分析不同的 third 计算方法"""
    print("=" * 70)
    print("分析不同的 third 计算方法")
    print("=" * 70)
    
    prime_61 = 2 ** 61 - 1
    prime_128 = 2 ** 128 - 159
    
    print("对于 prime = 2**61 - 1:")
    print(f"  prime % 3 = {prime_61 % 3}")
    print(f"  floor(prime/3) = {prime_61 // 3}")
    print(f"  ceil(prime/3)  = {(prime_61 + 2) // 3}")
    print(f"  2*floor + 1 = {2 * (prime_61 // 3) + 1}  ← 你的原始期望值")
    print(f"  2*ceil      = {2 * ((prime_61 + 2) // 3)}  ← 之前的计算方法")
    print()
    
    print("对于 prime = 2**128 - 159:")
    print(f"  prime % 3 = {prime_128 % 3}")
    print(f"  floor(prime/3) = {prime_128 // 3}")
    print(f"  ceil(prime/3)  = {(prime_128 + 2) // 3}")
    print(f"  2*floor + 1 = {2 * (prime_128 // 3) + 1}  ← 修正后的值")
    print(f"  2*ceil      = {2 * ((prime_128 + 2) // 3)}  ← 之前的值")
    print(f"  差值 = {2 * ((prime_128 + 2) // 3) - (2 * (prime_128 // 3) + 1)}")
    print("=" * 70)


if __name__ == "__main__":
    # 1. 验证算法
    verify_with_known_example()
    
    # 2. 测试 prime = 2**128 - 159
    test_prime_128()
    
    # 3. 分析不同方法
    analyze_different_methods()
    
    # 最终结果
    print("\n" + "=" * 70)
    print("最终结果")
    print("=" * 70)
    prime = 2 ** 128 - 159
    half, third = compute_half_third(prime)
    print(f"prime = {prime}")
    print(f"half   = {half}")
    print(f"third  = {third}")
    print("=" * 70)
