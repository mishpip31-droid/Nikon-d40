"""CPU-only prototype. Never emits a complete firmware or chooses physical RAM.

The proposed eighth row is placed in synthetic RAM by the test. Deployment of
descriptors, labels, cursor restoration and indication remains unresolved.
"""
import struct

ENTRY, LIMIT = 0x143FA4, 0x1441A8
INIT_ENTRY, INIT_LIMIT = 0x143EF6, ENTRY
MENU, PARENT, CUSTOM = 0x83CE58AC, 0x83CE53CC, 0x83CE593C
CURRENT, SAVED_MODE, WORK_MODE, WORK_TONE = 0x83CEE49C, 0x83CE957F, 0x83CED225, 0x83CED224


class Asm:
    def __init__(self, base):
        self.base, self.data, self.labels, self.fixups = base, bytearray(), {}, []

    @property
    def pc(self):
        return self.base + len(self.data)

    def word(self, value):
        self.data += struct.pack('>H', value)

    def label(self, name):
        assert name not in self.labels
        self.labels[name] = self.pc

    def ldi(self, reg, value, short=False):
        if short:
            assert 0 <= value <= 255
            self.word(0xC000 | value << 4 | reg)
        else:
            self.word(0x9F80 | reg)
            self.data += struct.pack('>I', value)

    def branch(self, cond, target):
        self.fixups.append((len(self.data), cond, target))
        self.word(0)

    def finish(self):
        for offset, cond, name in self.fixups:
            target = self.labels[name]
            displacement = target - (self.base + offset + 2)
            assert displacement % 2 == 0 and -256 <= displacement <= 254
            struct.pack_into('>H', self.data, offset, 0xE000 | cond << 8 | ((displacement // 2) & 255))
        return bytes(self.data)


def prototype():
    a = Asm(ENTRY)
    a.word(0x1708)                  # save r8
    a.word(0x1781)                  # save RP
    a.ldi(8, CURRENT)
    a.word(0x0480)                  # r0 = current menu
    a.ldi(1, MENU)
    a.word(0xAA10)
    a.branch(3, 'return')
    a.ldi(13, 0xC, True)
    a.word(0x0101)                  # row within viewport
    a.word(0x97A1)
    a.ldi(13, 0xE, True)
    a.word(0x0100)                  # viewport start
    a.word(0x97A0)
    a.word(0xA610)                  # r0 = absolute row index
    a.word(0xA800)
    a.branch(10, 'return')          # negative row rejected
    a.word(0xA870)
    a.branch(13, 'return')          # >7 rejected
    a.word(0xA860)
    a.branch(2, 'custom')
    a.word(0xA870)
    a.branch(3, 'preset')
    # Cinema uses the existing Custom storage layout: mode=5, tone=6.
    a.ldi(5, WORK_TONE)
    a.word(0x0651)
    a.ldi(2, 0xE3, True)
    a.word(0x8221)
    a.ldi(2, 0x18, True)
    a.word(0x9221)
    a.word(0x1651)
    a.ldi(0, 5, True)
    a.branch(0, 'apply')
    a.label('preset')
    a.word(0xA850)
    a.branch(3, 'apply')
    a.ldi(0, 6, True)               # Black-and-white row -> mode 6
    a.label('apply')
    a.word(0x8B03)                  # keep mode in r3
    a.ldi(5, SAVED_MODE)
    a.word(0x0651)
    a.ldi(2, 15, True)
    a.word(0x8221)
    a.word(0x8B02)
    a.word(0xB442)
    a.word(0x9221)
    a.word(0x1651)
    a.ldi(5, WORK_MODE)
    a.word(0x0651)
    a.ldi(2, 0xC3, True)
    a.word(0x8221)
    a.word(0x8B32)
    a.word(0xB422)
    a.word(0x9221)
    a.word(0x1651)
    a.ldi(4, 2, True)
    a.ldi(12, 0x1468AE)
    a.word(0x971C)                  # actual routine is explicitly a hook in CPU tests
    a.ldi(0, PARENT)
    a.branch(0, 'set_menu')
    a.label('custom')
    a.ldi(0, CUSTOM)
    a.label('set_menu')
    a.word(0x1480)
    a.label('return')
    a.word(0x0781)
    a.word(0x0708)
    a.word(0x9720)
    code = a.finish()
    assert ENTRY + len(code) <= LIMIT
    return code, a.labels


def in_memory_image(original):
    """Not flashable: no descriptors, label, display restoration or CRC patch."""
    code, labels = prototype()
    image = bytearray(original)
    image[ENTRY-0x40000:LIMIT-0x40000] = code + bytes.fromhex('9fa0') * ((LIMIT-ENTRY-len(code)) // 2)
    return bytes(image), labels


def initializer_prototype():
    """Index-based cursor restore, with Cinema recognized as Custom/tone=6."""
    a = Asm(INIT_ENTRY)
    a.word(0x1781)
    a.ldi(0, SAVED_MODE)
    a.word(0x0604)                  # saved optimize mode
    a.word(0xB044)
    a.word(0xA874)
    a.branch(10, 'valid')           # <7
    a.ldi(4, 0, True)
    a.branch(0, 'position')
    a.label('valid')
    a.word(0xA854)
    a.branch(2, 'custom')
    a.word(0xA864)
    a.branch(3, 'position')
    a.ldi(4, 5, True)               # black-and-white
    a.branch(0, 'position')
    a.label('custom')
    a.ldi(4, 6, True)
    a.ldi(0, WORK_TONE)
    a.word(0x0600)
    a.ldi(1, 0x1C, True)
    a.word(0x8210)
    a.ldi(1, 0x18, True)
    a.word(0xAA10)
    a.branch(3, 'position')
    a.ldi(4, 7, True)
    a.label('position')
    a.ldi(12, 0x132D0C)
    a.word(0x971C)
    a.ldi(0, 0x83CE98F4)
    a.word(0x9140)
    a.word(0x0781)
    a.word(0x9720)
    code = a.finish()
    assert INIT_ENTRY+len(code) <= INIT_LIMIT
    return code, a.labels


def with_initializer(original):
    image, _ = in_memory_image(original)
    code, labels = initializer_prototype()
    image = bytearray(image)
    image[INIT_ENTRY-0x40000:INIT_LIMIT-0x40000] = code + bytes.fromhex('9fa0') * ((INIT_LIMIT-INIT_ENTRY-len(code)) // 2)
    return bytes(image), labels
