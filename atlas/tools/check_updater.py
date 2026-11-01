#!/usr/bin/env python3
"""Read-only D40 B updater research. Never writes camera/flash or firmware files.

Original CPU routines are executed with explicit in-memory file/directory hooks.
Flash erase/program operations are recorded as abstract commands, never emulated
as electrical flash behavior. This does not establish safe installation/recovery.
"""
import argparse
import binascii
import hashlib
import json
import random
import struct
from pathlib import Path
from fr_color_machine import ColorMachine, EXPECTED

RAM=0x83CE0000
ENTRY=0x83CEE968
BUFFER=0x83CEE98A
EXP_SHA='8abfda8cc67f787be867fd3d348fd38fcc27b8e041702625d182a968052148a8'
A112_SHA='0cc92921d6b2ad5d5cfa070abeebdd9aaca224d326e42a26339e3ac384270394'


def sha(b):return hashlib.sha256(b).hexdigest()


def write_bytes(m,a,data):
    for start,region in m.regions:
        if start<=a and a+len(data)<=start+len(region):
            region[a-start:a-start+len(data)]=data
            return
    raise RuntimeError('Unmapped hook write')


def cstring(m,a,limit=128):
    out=bytearray()
    for i in range(limit):
        v=m.load(a+i,1)
        if not v:return out.decode('ascii')
        out.append(v)
    raise RuntimeError('Unterminated string')


def machine(original):
    m=ColorMachine(original);m.map(RAM,bytes(0x20000))
    return m


class FileHooks:
    def __init__(self,data,fail=None,short=None):
        self.data=data;self.position=0;self.log=[];self.fail=fail;self.short=short
        self.counts={'open':0,'seek':0,'read':0,'close':0}

    def event(self,name,**kw):
        self.counts[name]+=1
        self.log.append(dict(operation=name,index=self.counts[name],**kw))
        return self.fail==(name,self.counts[name])

    def open(self,m):
        fail=self.event('open',path=cstring(m,m.regs[4]))
        self.position=0;m.regs[4]=0xFFFFFFFF if fail else 7

    def close(self,m):
        self.event('close',handle=m.regs[4]);m.regs[4]=0

    def seek(self,m):
        fd,offset,whence,result=m.regs[4:8]
        assert fd==7 and whence==0
        fail=self.event('seek',offset=offset)
        if offset>len(self.data):fail=True
        if not fail:self.position=offset;m.store(result,offset,4)
        m.regs[4]=1 if fail else 0

    def read(self,m):
        fd,dest,count,actual=m.regs[4:8]
        assert fd==7
        fail=self.event('read',offset=self.position,count=count)
        n=min(count,max(0,len(self.data)-self.position))
        if self.short==self.counts['read']:n=max(0,n-1)
        if fail:n=0
        write_bytes(m,dest,self.data[self.position:self.position+n])
        self.position+=n;m.store(actual,n,4);m.regs[4]=1 if fail else 0

    @property
    def hooks(self):return {0x6C25E:self.open,0x6C2A0:self.close,0x6C40A:self.seek,0x6C2E2:self.read}


def probe_image(original,data,kind='B',fail=None,short=None):
    m=machine(original);m.store(0x83CEE980,0,4)
    write_bytes(m,ENTRY,(('BD400111.BIN' if kind=='B' else 'AD400112.BIN')+'\0').encode())
    m.store(ENTRY+0x14,len(data),4)
    fs=FileHooks(data,fail,short)
    steps=m.run(0xABBFE if kind=='B' else 0xABC6E,ENTRY,hooks=fs.hooks)
    return {'accepted':m.regs[4]==1,'kind_flag':m.load(0x83CEE980,4),
            'version_prefix':bytes(m.load(BUFFER+i,1) for i in range(9)).decode('ascii',errors='replace'),
            'instructions':steps,'file_calls':fs.log}


def match_name(original,names,pattern):
    m=machine(original);position=0;seen=[]
    def open_dir(m):
        assert cstring(m,m.regs[4])=='A:\\'
        m.store(m.regs[5],9,4);m.regs[4]=0
    def next_entry(m):
        nonlocal position
        if position==len(names):m.regs[4]=1;return
        name=names[position];position+=1;seen.append(name)
        write_bytes(m,m.regs[5],name.encode()+b'\0');m.regs[4]=0
    def close_dir(m):m.regs[4]=0
    m.regs[5]=ENTRY
    m.run(0xABE82,pattern,hooks={0xB8C78:open_dir,0xB8D7E:next_entry,0xB8EE8:close_dir})
    return {'matched':m.regs[4]==1,'name':cstring(m,ENTRY) if m.regs[4] else None,'visited':seen}


def flash_commands(original,comparisons=(1,),fail_operation=None):
    m=machine(original)
    write_bytes(m,0x83CE8658,original[0x11CB6C:0x11D52A])
    m.regs[8]=3;m.regs[9]=0;m.regs[14]=0x10001000;m.regs[15]=0x10000F00
    incoming_tag=original[0x120000:0x120010]
    user_tag=original[0x9534C:0x9535C]
    installed_tag=incoming_tag if comparisons==(1,) else user_tag if comparisons==(0,1) else bytes([0xA5])*16
    m.map(0x160000,installed_tag);m.map(0x81120000,incoming_tag)
    write_bytes(m,m.regs[14]-16,user_tag)
    commands=[]
    def erase(m):
        commands.append({'op':'erase','address':hex(m.regs[4]),'length':hex(m.regs[5])})
        m.regs[4]=0 if fail_operation=='erase' else 1
    def program(m):
        commands.append({'op':'program','address':hex(m.regs[4]),'source':hex(m.regs[5]),'length':hex(m.regs[6])})
        m.regs[4]=0 if fail_operation=='program' else 1
    steps=m.run(0x83CE877C,stop=0x83CE8892,hooks={0x83CE8954:erase,0x83CE89E0:program})
    return {'instructions':steps,'attempts_remaining':m.regs[8],'commands':commands,
            'installed_tag_hex':installed_tag.hex(),'comparison_routine':'Original CPU code executed',
            'scope':'Original supervisor and tag comparisons; physical erase/program calls are stubs'}


def verify(original,experimental,afile):
    assert sha(original)==EXPECTED
    if experimental is not None:assert sha(experimental)==EXP_SHA
    if afile is not None:assert sha(afile)==A112_SHA
    # Metadata layout is read through pointers by the actual original validator.
    result={'base_sha256':EXPECTED,'scope':'Offline CPU research with explicit external-operation models',
            'camera_tested':False,'installability_proven':False,'recovery_proven':False}
    images={'original_B':original}
    if experimental is not None:images['EXP01']=experimental
    initial={}
    for name,data in images.items():
        probe=probe_image(original,data);assert probe['accepted'] and probe['kind_flag']==1
        assert probe['version_prefix']=='Ver.1.11A'
        initial[name]=probe
    # These prefixes intentionally vary to test whether this PRECHECK compares versions.
    version_ptr=int.from_bytes(original[0xAFBF0:0xAFBF4],'big')-0x40000
    variations={}
    for text in ('Ver.1.00A','Ver.1.11A','Ver.9.99A','XXXXXXXXX'):
        data=bytearray(original);data[version_ptr:version_ptr+9]=text.encode()
        q=probe_image(original,bytes(data));assert q['accepted']
        variations[text]=q['accepted']
    rejected=[]
    for n in (0,0x40002,len(original)-1,len(original)+1):
        data=original[:n] if n<=len(original) else original+b'\0'
        assert not probe_image(original,data)['accepted'];rejected.append('B_size_'+str(n))
    sig=int.from_bytes(original[0xAFBF4:0xAFBF8],'big')-0x40000
    bad=bytearray(original);bad[sig]^=1
    assert not probe_image(original,bytes(bad))['accepted'];rejected.append('wrong_identification_string')
    for operation,indices in (('open',(1,)),('seek',range(1,5)),('read',range(1,5))):
        for i in indices:
            assert not probe_image(original,original,fail=(operation,i))['accepted'];rejected.append(f'{operation}_failure_{i}')
    for i in range(1,5):
        assert not probe_image(original,original,short=i)['accepted'];rejected.append(f'short_read_{i}')
    result['B_precheck']={'images':initial,'version_prefix_tests':variations,'negative_cases':rejected,
                          'crc_checked_here':False,'meaning':'Size/signature/reads pass; version prefix is copied, not ordered or compared in this path'}
    if afile is not None:
        ares=[]
        for data in (afile,afile[:-2],afile[:-1],afile+b'\0'):
            p=probe_image(original,data,'A');assert p['accepted']==(len(data) in (0x40000,0x40002))
            ares.append({'size':len(data),'accepted':p['accepted']})
        result['A_precheck']={'cases':ares,'scope':'B-side size/header reader for A; not A firmware execution'}

    names=['D40_Cinema2383_EXP01_NOT_CAMERA_TESTED.bin','BD400111.bin','BD400000.BIN','BD40ABCD.BIN','BD40011.BIN','BD4001111.BIN','AD400111.BIN','BD40.111.BIN']
    matches={name:match_name(original,[name],0xE4BC8) for name in names}
    assert [k for k,v in matches.items() if v['matched']]==['BD400111.bin','BD400000.BIN','BD40ABCD.BIN','BD40.111.BIN']
    first=match_name(original,['readme.txt','BD400111.BIN','BD400999.BIN'],0xE4BC8)
    assert first['name']=='BD400111.BIN'
    result['file_names']={'pattern':'BD40????.BIN','cases':matches,'first_match':first,
                          'meaning':'Case-insensitive exact-length match; question marks accept any non-NUL byte, not just digits'}

    # Independently verify the ROM table against the polynomial recurrence.
    table=list(struct.unpack_from('>256H',original,0x83A88))
    generated=[]
    for byte in range(256):
        v=byte<<8
        for _ in range(8):v=((v<<1)^0x1021 if v&0x8000 else v<<1)&65535
        generated.append(v)
    assert table==generated
    def crc_model(data):
        value=0
        for byte in data:value=((value<<8)^table[(value>>8)^byte])&65535
        return value
    vectors=[bytes([x]) for x in range(256)]+[b'',b'123456789']
    rng=random.Random(40)
    vectors += [rng.randbytes(n) for n in (2,3,16,255,256,4096,8192)]
    steps=0
    for data in vectors:
        m=ColorMachine(original);m.map(0x81000000,data+b'\0');m.regs[5]=0x81000000
        steps+=m.run(0x44CCC,len(data),budget=200000)
        assert m.regs[4]==crc_model(data)==binascii.crc_hqx(data,0)
    full={}
    for name,data in images.items():
        v=crc_model(data);assert v==binascii.crc_hqx(data,0)==0
        corrupt=bytearray(data);corrupt[0x2E3562]^=1
        assert crc_model(corrupt)!=0
        full[name]={'whole_image_residual':v,'one_bit_error_rejected':True,'sha256':sha(data)}
    result['CRC']={'original_cpu_test_vectors':len(vectors),'instructions':steps,'ROM_table_entries_verified':256,
                    'whole_images':full,'whole_image_method':'Exact integer loop model plus independent binascii; whole images not instruction-by-instruction emulated'}
    schedules={}
    for key,cmp,fail in [('keep_wallpaper',(1,),None),('keep_user_wallpaper',(0,1),None),('replace_wallpaper',(0,0),None),('erase_fails',(1,),'erase'),('program_fails',(1,),'program')]:
        schedules[key]=flash_commands(original,cmp,fail)
    assert len([x for x in schedules['erase_fails']['commands'] if x['op']=='erase'])==3
    assert schedules['erase_fails']['attempts_remaining']==0
    assert schedules['program_fails']['attempts_remaining']==0
    assert len([x for x in schedules['program_fails']['commands'] if x['op']=='program'])==3
    normal=[x for x in schedules['keep_wallpaper']['commands'] if x['op']=='program']
    assert [(int(x['address'],16),int(x['length'],16)) for x in normal]==[(0x120000,0x40000),(0x1B0000,0x260000),(0x40000,0xB0000)]
    assert schedules['keep_user_wallpaper']['commands']==schedules['keep_wallpaper']['commands']
    replacement=[x for x in schedules['replace_wallpaper']['commands'] if x['op']=='program']
    assert [(int(x['address'],16),int(x['length'],16)) for x in replacement]==[(0x160000,0x10000),(0x120000,0x40000),(0x1B0000,0x260000),(0x40000,0xB0000)]
    for x in normal:assert int(x['source'],16)==0x81000000+int(x['address'],16)-0x40000
    if experimental is not None:
        changed=[i for i,(a,b) in enumerate(zip(original,experimental)) if a!=b]
        for off in changed:
            address=off+0x40000
            assert any(int(x['address'],16)<=address<int(x['address'],16)+int(x['length'],16) for x in normal)
        result['EXP01_program_coverage']={'changed_bytes':len(changed),'all_in_scheduled_program_ranges':True,'physical_programming_tested':False}
    result['flash_supervisor']=schedules
    result['result']='PASS'
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('original_B');p.add_argument('--experimental');p.add_argument('--original_A');p.add_argument('--output',required=True)
    args=p.parse_args();original=Path(args.original_B).read_bytes()
    experimental=Path(args.experimental).read_bytes() if args.experimental else None
    afile=Path(args.original_A).read_bytes() if args.original_A else None
    report=verify(original,experimental,afile)
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k in ('result','base_sha256','CRC','EXP01_program_coverage','camera_tested','installability_proven','recovery_proven')},indent=2))


if __name__=='__main__':main()
