#!/usr/bin/env python3
"""Validate an equal-size patch proposal IN MEMORY. Does not save firmware.
A valid CRC/hash is not evidence that code is correct or safe to flash.
"""
import argparse,binascii,hashlib,json
from pathlib import Path
from atlas import require_b,EXPECTED,hx

def review(b,manifest):
    if manifest.get('base_sha256')!=EXPECTED['BD400111.bin']:
        raise ValueError('Manifest must pin the exact B 1.11 original')
    proposed=bytearray(b);used=set();result=[]
    patches=manifest.get('patches')
    if not isinstance(patches,list) or not patches:raise ValueError('No concrete changes in manifest')
    for p in patches:
        off=int(p['file_offset'],0);old=bytes.fromhex(p['before_hex']);new=bytes.fromhex(p['after_hex'])
        if not old or old==new or len(old)!=len(new):raise ValueError('Require nonempty, non-identical, equal-size before/after bytes')
        if not 0<=off<=len(b)-2-len(old):raise ValueError('Out of bounds or overlaps trailing CRC')
        if not p.get('reason') or not p.get('evidence'):raise ValueError('Every change needs reason and evidence')
        rr=set(range(off,off+len(old)))
        if rr&used:raise ValueError('Overlapping patches')
        if b[off:off+len(old)]!=old:raise ValueError('Original bytes do not match manifest')
        used.update(rr);proposed[off:off+len(old)]=new
        result.append(dict(file_offset=hx(off),length=len(old),reason=p['reason']))
    crc=binascii.crc_hqx(proposed[:-2],0);proposed[-2:]=crc.to_bytes(2,'big')
    return dict(review='BYTE_CONSISTENCY_ONLY',changes=result,candidate_crc=f'0x{crc:04x}',
                candidate_sha256=hashlib.sha256(proposed).hexdigest(),firmware_written=False,
                hardware_verified=False,flashability_verified=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware');p.add_argument('manifest')
    a=p.parse_args();print(json.dumps(review(require_b(a.firmware),json.loads(Path(a.manifest).read_text())),indent=2))
