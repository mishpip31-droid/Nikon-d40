"""Read-only color models derived from D40 B 1.11; no camera/firmware writes."""
import struct


def matrices(blob, rom, count):
    return [list(struct.unpack_from('>9h', blob, rom-0x40000+18*i)) for i in range(count)]


def expand_profile(blob, index):
    """Exact integer recurrence; return all bytes generated, including mono tail."""
    if 0 <= index < 48:
        first, second = 0x3404fb+index, 0x3404cb+index
        start, length, bits = 0x34052b+511*index, 511, 4
    elif 1000 <= index < 1005:
        i = index-1000
        first, second = 0x33ffc6+i, 0x33ffc1+i
        start, length, bits = 0x33ffcb+256*i, 256, 2
    else:
        raise ValueError('Only observed table indices 0..47 and 1000..1004')
    result = [blob[first-0x40000], blob[second-0x40000]]
    for byte in blob[start-0x40000:start-0x40000+length]:
        for shift in range(8-bits, -1, -bits):
            delta = ((byte >> shift) & ((1 << bits)-1)) - (1 << (bits-1))
            result.append((2*result[-1]-result[-2]+delta) & 255)
    return result


def saturation_pair(blob, sat, family, x, q):
    """Known input range only; physical meanings of x and q are unresolved."""
    if sat not in range(4) or family not in range(3) or not 60 <= x <= 255:
        raise ValueError('Outside analyzed selector domain')
    x = min(x,120)
    k = ((x-60)*0x1556) >> 16
    k2 = k + (x < 120)
    row = 0 if q < 143 else 77 if q > 218 else q-142
    if sat == 0:
        start = (0x33fddb,0x33fc07,0x33fa33)[family] + 6*row
    else:
        start = 0x33ffaf + 6*(sat-1)
    return blob[start-0x40000+k], blob[start-0x40000+k2], k, x


def selected_profile(blob, sat, family, x, q):
    first, second, k, x = saturation_pair(blob,sat,family,x,q)
    # The odd remainders deliberately take the default/first branch.
    return second if x-60-12*k in (6,8,10) else first


def f32(value):
    return struct.unpack('>f', struct.pack('>f', value))[0]


def hue_model(blob, matrix, hue_index, family):
    """Host float32 model, NOT a bit-exact proof of Nikon's FP runtime."""
    if family not in range(3) or hue_index not in range(7):
        raise ValueError('Valid hue domain is 0..6, family 0..2')
    a,b,c,d = [f32(v/10000) for v in
               (struct.unpack_from('>h',blob,0x2f1af0+2*((family*4+k)*7+hue_index))[0]
                for k in range(4))]
    result = list(matrix)
    for col in range(3):
        for row, p, q in ((1,a,b),(2,c,d)):
            value = int(f32(f32(p*matrix[3+col]) + f32(q*matrix[6+col])))
            result[row*3+col] = min(511,max(-511,value))
    return result
