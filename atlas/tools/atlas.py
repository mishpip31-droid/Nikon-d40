#!/usr/bin/env python3
"""Read-only, hash-locked analysis of original Nikon D40 firmware.
Writes analysis to a separate directory; never writes firmware or a device.
All ranges are half-open. Python 3 standard library only.
"""
import argparse, binascii, collections, csv, hashlib, json, math, re, struct
from pathlib import Path

EXPECTED = {
    'BD400111.bin': 'b9df48d461e875dce4ba84da88164af170dfc48ad9f7674859623bad0401032e',
    'AD400111.bin': 'ff96a874d3a22f9c18c610bd5bf55f4e6a53603c865fdb8e913a1d53591db5c9',
    'AD400112.bin': '0cc92921d6b2ad5d5cfa070abeebdd9aaca224d326e42a26339e3ac384270394',
}
BASE = 0x40000
DELTA = 0x83bcbaec
DATA_START, DATA_END = 0x1144c4, 0x11cb6c
COPY_END = 0x11d52a
ACTION_BASE, SCREEN_BASE = 0x114cac, 0x116644
STRING_BASE = 0x2548b4

def read_firmware(path):
    path = Path(path); b = path.read_bytes(); sha = hashlib.sha256(b).hexdigest()
    if sha not in EXPECTED.values():
        raise ValueError('Unsupported SHA-256; do not reuse these addresses on another firmware')
    if binascii.crc_hqx(b[:-2], 0) != int.from_bytes(b[-2:], 'big'):
        raise ValueError('Invalid trailing CRC-16/XMODEM')
    return b

def require_b(path):
    b = read_firmware(path)
    if hashlib.sha256(b).hexdigest() != EXPECTED['BD400111.bin']:
        raise ValueError('This command requires B 1.11')
    return b

def jsave(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf8')

def csave(p, fields, rows):
    with p.open('w', encoding='utf8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

def u16(b, o): return struct.unpack_from('>H', b, o)[0]
def u32(b, o): return struct.unpack_from('>I', b, o)[0]
def hx(v): return f'0x{v:08x}'
def label(raw):
    return ''.join(chr(x) if 32 <= x < 127 else f'\\x{x:02x}' for x in raw)

def strings(b):
    ptrs = [u32(b, STRING_BASE+i*4)-BASE for i in range(602)]
    if ptrs != sorted(ptrs) or ptrs[0] != STRING_BASE+4*602:
        raise ValueError('English string table invariant failed')
    return [dict(index=i, file_offset=hx(a), rom_address=hx(a+BASE),
                 length=z-a, text=label(b[a:z])) for i,(a,z) in enumerate(zip(ptrs,ptrs[1:]))]

def menus(b, ss):
    result = []
    for o in range(DATA_START, DATA_END-32, 4):
        h = struct.unpack_from('>10H3I', b, o)
        if not ((h[0] < 601 or h[0] == 65535) and (h[1] < 601 or h[1] == 65535)
                and h[3] in (0,1) and h[4] <= 40 and h[5] <= 40 and (h[9] < 170 or h[9] == 65535)
                and 0x83ce7f00 <= h[11] < 0x83ce8080
                and (h[10] == 0 or 0x83ce2000 <= h[10] < 0x83ce8000)):
            continue
        n, a = h[5], h[12]-DELTA
        if n and not (DATA_START <= a and a+16*n <= DATA_END): continue
        if not n and h[12] != 0: continue
        screen_off = SCREEN_BASE+12*h[9] if h[9]<170 else None
        screen = struct.unpack_from('>3I', b, screen_off) if screen_off is not None else (0,0,0)
        elements = []
        for i in range(n):
            p = a+16*i; v = struct.unpack_from('>6HI', b, p)
            ac = ACTION_BASE+12*v[5] if v[5] < 546 else None
            elements.append(dict(index=i, file_offset=hx(p), ram_address=hx(p+DELTA),
                text_index=v[1], text=ss[v[1]]['text'] if v[1] < len(ss) else '',
                action_index=v[5], action_record=hx(ac) if ac is not None else None,
                action_pc=hx(u32(b,ac+8)) if ac is not None else None,
                submenu_ram=hx(v[6]), fields=[hx(x) for x in v]))
        result.append(dict(file_offset=hx(o), ram_address=hx(o+DELTA),
            title=ss[h[0]]['text'] if h[0]<len(ss) else '',
            subtitle=ss[h[1]]['text'] if h[1]<len(ss) else '',
            count=n, parent_ram=hx(h[10]), screen_index=h[9], screen_record=hx(screen_off) if screen_off is not None else None,
            callback_4_pc=hx(screen[1]), callback_8_pc=hx(screen[2]),
            raw_header=[hx(x) for x in h], elements=elements,
            confidence='structural; execution and visibility not established for every descriptor'))
    known = {m['ram_address'] for m in result}
    unresolved=[]
    for m in result:
        for e in m['elements']:
            a=e['submenu_ram']
            if int(a,16) and a not in known:
                unresolved.append(dict(from_menu=m['ram_address'],element=e['index'],target=a))
    return result, unresolved

def whole_file_stats(name, b):
    sha=hashlib.sha256(b).hexdigest()
    blocks=[]
    for o in range(0,len(b),4096):
        s=b[o:o+4096]; n=len(s); c=collections.Counter(s)
        entropy=-sum((v/n)*math.log2(v/n) for v in c.values())
        blocks.append(dict(file_offset=hx(o),size=n,entropy=round(entropy,5),
                           ff_bytes=c[255],zero_bytes=c[0]))
    padding=[dict(start=hx(m.start()),end_exclusive=hx(m.end()),size=m.end()-m.start(),
                  fill='ff',usable_for_patch=False)
             for m in re.finditer(b'\xff{256,}',b)]
    return dict(filename=name,size=len(b),sha256=sha,crc16_xmodem=hx(int.from_bytes(b[-2:],'big')),
                crc_offset=hx(len(b)-2),crc_endian='big',known_original=True),blocks,padding

def literal_index(b):
    # All aligned LDI:32 byte patterns. Some may be data, not executed instructions.
    return [dict(file_offset=hx(o),rom_address=hx(o+BASE),register=b[o+1]&15,
                 value=hx(u32(b,o+2)),confidence='byte-pattern candidate')
            for o in range(0,len(b)-5,2) if b[o]==0x9f and b[o+1]&0xf0==0x80]

def extra_indexes(b, output):
    # 15 language tables referenced by the language selector. Preserve the
    # firmware's byte encoding; no assumption that it is UTF-8 or Windows-1251.
    language_bases=set()
    for o in range(0x5b14e,0x5b582,2):
        if b[o]==0x9f and b[o+1]&0xf0==0x80:
            v=u32(b,o+2)
            if 0x280000<v<0x320000:
                p=[u32(b,v-BASE+4*i) for i in range(602)]
                if p==sorted(p) and p[0]==v+2408:language_bases.add(v-BASE)
    langs=[];rows=[]
    for base in sorted(language_bases):
        pp=[u32(b,base+4*i)-BASE for i in range(602)]
        langs.append(dict(table_file=hx(base),table_rom=hx(base+BASE),entries=601,
                          sample=label(b[pp[0]:pp[1]]),encoding='custom byte/glyph encoding'))
        for i,(a,z) in enumerate(zip(pp,pp[1:])):
            rows.append(dict(table_file=hx(base),index=i,file_offset=hx(a),length=z-a,text=label(b[a:z])))
    jsave(output/'language_tables.json',langs)
    csave(output/'localized_menu_strings.csv',list(rows[0]),rows)
    # The PTP wire property codes and datatypes are little endian even though
    # FR instructions and descriptor pointers in the table are big endian.
    props=[]
    for o in range(0x9a7ac,0x9abfc,12):
        p,cb4,cb8=struct.unpack_from('>3I',b,o);z=p-DELTA
        code,typ=struct.unpack_from('<HH',b,z)
        props.append(dict(table_file=hx(o),property_code=f'0x{code:04x}',datatype=f'0x{typ:04x}',
            descriptor_file=hx(z),descriptor_ram=hx(p),callback_4_pc=hx(cb4),callback_8_pc=hx(cb8)))
    csave(output/'ptp_properties.csv',list(props[0]),props)
    # Three separately terminated operation tables near the PTP constants.
    def operation(o):
        code,pad,pc=struct.unpack_from('>HHI',b,o)
        return pad==0 and (0x1000<code<0x1100 or 0x9000<=code<0xa000) and pc%2==0 and BASE<=pc<BASE+len(b)
    operations=[]
    for seed in [0x99ec4,0x99eec,0x99f54]:
        a,z=seed,seed
        while operation(z):z+=8
        operations.extend(dict(table_start=hx(a),table_file=hx(o),operation_code=f'0x{u16(b,o):04x}',handler_pc=hx(u32(b,o+4))) for o in range(a,z,8))
    csave(output/'ptp_operations.csv',list(operations[0]),operations)
    calls=[]
    for o in range(0,len(b)-7,2):
        if b[o]==0x9f and b[o+1]&0xf0==0x80:
            r=b[o+1]&15;w=u16(b,o+6)
            if w in (0x9710+r,0x9f10+r):
                target=u32(b,o+2)
                calls.append(dict(load_file=hx(o),call_file=hx(o+6),target=hx(target),
                                   delay_slot=w==0x9f10+r,confidence='adjacent byte-pattern candidate; no CFG proof'))
    if calls:csave(output/'direct_call_candidates.csv',list(calls[0]),calls)
    return dict(language_tables=len(langs),ptp_property_records=len(props),ptp_operation_records=len(operations),direct_call_patterns=len(calls))

def diff_a(a, b):
    ranges=[]; start=None
    for i,(x,y) in enumerate(zip(a,b)):
        if x!=y and start is None: start=i
        if x==y and start is not None:
            ranges.append(dict(start=hx(start),end_exclusive=hx(i),length=i-start));start=None
    if start is not None:ranges.append(dict(start=hx(start),end_exclusive=hx(len(a)),length=len(a)-start))
    # Unique 32-byte anchors are evidence of relocation, not a semantic function diff.
    def anchors(blob):
        m=collections.defaultdict(list)
        for o in range(0,len(blob)-31,2):
            v=blob[o:o+32]
            if len(set(v)) >= 8:m[v].append(o)
        return {v:oo[0] for v,oo in m.items() if len(oo)==1}
    x,y=anchors(a),anchors(b)
    shifts=collections.Counter(y[v]-o for v,o in x.items() if v in y)
    return dict(changed_bytes=sum(x!=y for x,y in zip(a,b)),changed_ranges=ranges,
                top_unique_anchor_shifts=[dict(delta=d,anchors=n) for d,n in shifts.most_common(20)],
                interpretation='Matching anchors are not portable patch offsets; function boundaries and semantics remain unverified')

def analyze(directory, output):
    directory,output=Path(directory),Path(output)
    if output.resolve()==directory.resolve():raise ValueError('Output must be a separate directory')
    output.mkdir(parents=True,exist_ok=True)
    blobs={n:read_firmware(directory/n) for n in EXPECTED}
    inventory=[]
    for n,b in blobs.items():
        ident,blocks,pads=whole_file_stats(n,b); inventory.append(ident)
        csave(output/(n+'.blocks.csv'),['file_offset','size','entropy','ff_bytes','zero_bytes'],blocks)
        jsave(output/(n+'.padding.json'),pads)
    jsave(output/'firmware_inventory.json',inventory)
    b=blobs['BD400111.bin'];ss=strings(b);mm,unresolved=menus(b,ss)
    csave(output/'english_menu_strings.csv',['index','file_offset','rom_address','length','text'],ss)
    jsave(output/'menus.json',mm)
    csave(output/'menus.csv',['file_offset','ram_address','title','subtitle','count','screen_index','callback_4_pc','callback_8_pc'],
          [{k:m[k] for k in ['file_offset','ram_address','title','subtitle','count','screen_index','callback_4_pc','callback_8_pc']} for m in mm])
    csave(output/'menu_edges.csv',['from_ram','element','label','to_ram'],
          [dict(from_ram=m['ram_address'],element=e['index'],label=e['text'],to_ram=e['submenu_ram'])
           for m in mm for e in m['elements'] if int(e['submenu_ram'],16)])
    actions=[dict(index=i,file_offset=hx(ACTION_BASE+12*i),ram_address=hx(ACTION_BASE+12*i+DELTA),
                  raw0=hx(u32(b,ACTION_BASE+12*i)),raw1=hx(u32(b,ACTION_BASE+12*i+4)),
                  handler_pc=hx(u32(b,ACTION_BASE+12*i+8))) for i in range(546)]
    csave(output/'action_dispatch.csv',list(actions[0]),actions)
    screens=[dict(index=i,file_offset=hx(SCREEN_BASE+12*i),ram_address=hx(SCREEN_BASE+12*i+DELTA),
                  flags=hx(u32(b,SCREEN_BASE+12*i)),callback_4_pc=hx(u32(b,SCREEN_BASE+12*i+4)),
                  callback_8_pc=hx(u32(b,SCREEN_BASE+12*i+8))) for i in range(170)]
    csave(output/'screen_dispatch.csv',list(screens[0]),screens)
    literals=literal_index(b);csave(output/'ldi32_candidates.csv',list(literals[0]),literals)
    vectors=[dict(slot=i,vector_number=255-i,file_offset=hx(0xafc00+i*4),
                  handler_pc=hx(u32(b,0xafc00+i*4))) for i in range(256)]
    csave(output/'vectors_B.csv',list(vectors[0]),vectors)
    jsave(output/'A_111_to_112_diff.json',diff_a(blobs['AD400111.bin'],blobs['AD400112.bin']))
    checks=dict(original_hashes_and_crcs='PASS',menu_descriptors=len(mm),
                element_references=sum(m['count'] for m in mm),
                unique_element_records=len({e['file_offset'] for m in mm for e in m['elements']}),
                unresolved_submenu_links=unresolved,english_entries_with_bounded_length=len(ss),
                raw_ldi32_candidates=len(literals),all_input_bytes_scanned=True,
                all_instructions_understood=False,hardware_tested=False,flashable_patch_created=False)
    checks.update(extra_indexes(b,output))
    jsave(output/'analysis_checks.json',checks)
    print(json.dumps(checks,ensure_ascii=False,indent=2))

def xref(path,value):
    b=require_b(path);p=0;out=[];needle=value.to_bytes(4,'big')
    while True:
        p=b.find(needle,p)
        if p<0:break
        ldi=p>=2 and p%2==0 and b[p-2]==0x9f and b[p-1]&0xf0==0x80
        out.append(dict(file_offset=hx(p),rom_address=hx(p+BASE),
            ram_alias=hx(p+DELTA) if DATA_START<=p<COPY_END else None,
            ldi32_pattern=ldi,kind='literal match; not proof of execution'))
        p+=1
    print(json.dumps(out,indent=2))

def main():
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('analyze');p.add_argument('firmware_dir');p.add_argument('output_dir')
    p=sub.add_parser('xref');p.add_argument('firmware');p.add_argument('value',type=lambda x:int(x,0))
    p=sub.add_parser('map');p.add_argument('firmware');p.add_argument('space',choices=['file','rom','ram']);p.add_argument('value',type=lambda x:int(x,0))
    p=sub.add_parser('disasm');p.add_argument('firmware');p.add_argument('start',type=lambda x:int(x,0));p.add_argument('end',type=lambda x:int(x,0));p.add_argument('--base',type=lambda x:int(x,0),default=None)
    a=ap.parse_args()
    if a.cmd=='analyze':analyze(a.firmware_dir,a.output_dir)
    elif a.cmd=='xref':xref(a.firmware,a.value)
    elif a.cmd=='map':
        b=require_b(a.firmware)
        if a.space=='file':off=a.value
        elif a.space=='rom':off=a.value-BASE
        elif DATA_START+DELTA<=a.value<COPY_END+DELTA:off=a.value-DELTA
        else:raise ValueError('No established file mapping for this RAM address; do not subtract a global delta')
        if not 0<=off<len(b)-2:raise ValueError('Outside mapped B payload')
        print(json.dumps(dict(file_offset=hx(off),rom_address=hx(off+BASE),
            ram_alias=hx(off+DELTA) if DATA_START<=off<COPY_END else None),indent=2))
    else:
        from fr_decode import listing
        b=read_firmware(a.firmware);base=a.base if a.base is not None else (BASE if len(b)>300000 else 0xc0000)
        print('FILE     CPU_PC   BYTES        MNEMONIC  OPERANDS')
        print('\n'.join(listing(b,a.start,a.end,base)))

if __name__=='__main__':main()
