"""Regression checks on original bytes and rejection of invalid patch proposals.
Usage: python tools/test_atlas.py /path/to/original/firmware_directory
"""
import json,sys,unittest
from pathlib import Path
from atlas import read_firmware,require_b,strings,menus,EXPECTED,DELTA,u32
from fr_decode import decode
from patch_review import review

ROOT=Path(sys.argv.pop(1)) if len(sys.argv)>1 else Path('originals')
B=require_b(ROOT/'BD400111.bin')

class AtlasChecks(unittest.TestCase):
    def test_originals(self):
        for n in EXPECTED:read_firmware(ROOT/n)

    def test_reset_and_copy_instructions(self):
        self.assertEqual(u32(B,0xafffc),0xc0f90)
        for off,expected in [(0x812b6,0x86a8),(0x812c0,0x1544c4),(0x812c6,0x83cdffb0),
                             (0x812d4,0x9be),(0x812de,0x15cb6c),(0x812e4,0x83ce8658),
                             (0x8128e,0x19130),(0x81294,0x83ce9018)]:
            self.assertEqual(u32(B,off),expected)
        self.assertEqual(0x1544c4-0x40000+DELTA,0x83cdffb0)
        self.assertEqual(0x11cb6c+DELTA,0x83ce8658)

    def test_menu_graph_and_known_dispatch(self):
        mm,unresolved=menus(B,strings(B));self.assertEqual(len(mm),205);self.assertFalse(unresolved)
        known={m['ram_address'] for m in mm}
        self.assertTrue(all(int(m['parent_ram'],16)==0 or m['parent_ram'] in known for m in mm))
        m=next(x for x in mm if x['ram_address']=='0x83ce58ac')
        self.assertEqual(m['count'],7)
        self.assertEqual(m['callback_4_pc'],'0x00143ef6')
        self.assertEqual([x['action_pc'] for x in m['elements']],['0x00143fa4']*7)
        self.assertEqual([x['text'] for x in m['elements']],['Normal','Softer','Vivid','More vivid','Portrait','Black-and-white','Custom'])

    def test_ptp_endianness(self):
        self.assertEqual(u32(B,0x9a8f0),0x83ce2f1b)
        self.assertEqual(B[0x11742f:0x117433].hex(),'2ad00200')
        self.assertEqual(u32(B,0x9a8f4),0x398698)
        self.assertEqual(u32(B,0x99f20),0x8510e)

    def test_decode_instructions_and_lengths(self):
        samples=[('9f8083ced224',6,'LDI:32','#0x83ced224,r0'),
                 ('9b150000',4,'LDI:20','#0x10000,r5'),
                 ('b5a0',2,'LSL','#26,r0'),('b1c0',2,'LSR','#28,r0'),
                 ('1781',2,'ST','RP,@-r15'),('e0ff',2,'BRA','0x40000'),
                 ('9f20',2,'RET:D',''),('a5c1',2,'ADD2','#-4,r1')]
        for s,n,m,o in samples:self.assertEqual(decode(bytes.fromhex(s),0),(n,m,o))

    def proposal(self):
        return dict(base_sha256=EXPECTED['BD400111.bin'],patches=[dict(file_offset='0x255334',
              before_hex=B[0x255334:0x255335].hex(),after_hex='58',reason='unit test only',evidence='never emitted as firmware')])

    def test_review_in_memory_only(self):
        before=B[:];r=review(B,self.proposal())
        self.assertFalse(r['firmware_written']);self.assertFalse(r['flashability_verified']);self.assertEqual(before,B)

    def test_reject_bad_base(self):
        p=self.proposal();p['base_sha256']='0'*64
        with self.assertRaises(ValueError):review(B,p)

    def test_reject_changed_original_bytes(self):
        p=self.proposal();p['patches'][0]['before_hex']='00'
        with self.assertRaises(ValueError):review(B,p)

    def test_reject_overlap(self):
        p=self.proposal();p['patches']*=2
        with self.assertRaises(ValueError):review(B,p)

    def test_reject_length_and_crc_changes(self):
        p=self.proposal();p['patches'][0]['after_hex']='1122'
        with self.assertRaises(ValueError):review(B,p)
        p=self.proposal();p['patches'][0]['file_offset']=hex(len(B)-2)
        with self.assertRaises(ValueError):review(B,p)

if __name__=='__main__':unittest.main()
