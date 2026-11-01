"""Summarise analyze.py output into a Markdown overview (Russian).

Usage: python3 report.py A|B outdir firmware.bin > MAP.md
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

kind, out, fw = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
data = fw.read_bytes()
rows = list(csv.DictReader(open(out / 'functions.csv')))
summ = json.load(open(out / 'summary.json'))
cg = json.load(open(out / 'callgraph.json'))
xr = json.load(open(out / 'xrefs.json'))
osc = json.load(open(out / 'os_calls.json'))
strs = list(csv.DictReader(open(out / 'strings.csv')))
base = 0x40000 if kind == 'B' else 0xC0000

# confidence: high = reachable from vectors/atlas code via resolved calls;
# medium = otherwise has callers, or >= 20 insns; low = rest
roots = [r['entry'] for r in rows if 'vector' in r['source'] or 'task' in r['source'] or
         ('atlas' in r['source'] and not r['bad_at'])]
reach = set(roots)
stack = list(roots)
while stack:
    a = stack.pop()
    for b in cg.get(a, []):
        if b not in reach:
            reach.add(b)
            stack.append(b)
for r in rows:
    if r['bad_at']:
        r['confidence'] = 'invalid'
    elif r['entry'] in reach:
        r['confidence'] = 'high'
    elif int(r['callers']) > 0 or int(r['insns']) >= 20:
        r['confidence'] = 'medium'
    else:
        r['confidence'] = 'low'
with open(out / 'functions.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
conf = Counter(r['confidence'] for r in rows)

P = print
P(f'# Карта функций части {kind} ({fw.name})\n')
P('Сгенерировано `tools/frdis/analyze.py` + `report.py`. Статический анализ, '
  'без исполнения; назначения — по данным, а не по документации Nikon.\n')
P('## Итог\n')
P('| Показатель | Значение |\n|---|---:|')
for k, label in [('functions', 'Функций'), ('instructions', 'Инструкций'),
                 ('code_bytes_covered', 'Байт кода покрыто'),
                 ('image_bytes', 'Размер образа'),
                 ('functions_with_bad_decode', 'Функций с ошибкой декодирования'),
                 ('unresolved_indirect_jumps', 'Неразрешённых косвенных переходов'),
                 ('memory_addresses_referenced', 'Адресов памяти с известным обращением'),
                 ('direct_io_addresses', 'Адресов прямой адресации I/O'),
                 ('strings', 'ASCII-строк')]:
    P(f'| {label} | {summ[k]} |')
P('\nДостоверность функций: ' + ', '.join(f'{k}: {v}' for k, v in conf.most_common()) +
  '. high — достижима от векторов, таблицы задач или адресов атласа по разрешённым вызовам; medium — '
  'есть вызывающие или не меньше 20 инструкций; low — короткая, без вызывающих '
  '(возможны данные); invalid — обход упёрся в недопустимую инструкцию.')
P('\nИсточник обнаружения функций (функция может иметь несколько):\n')
P('| Источник | Смысл | Кол-во |\n|---|---|---:|')
expl = {'vector': 'таблица векторов', 'call': 'цель прямого/разрешённого вызова',
        'tailjmp': 'хвостовой переход', 'atlas': 'адрес из атласа v15',
        'constptr': 'константа-указатель в коде', 'ptrtable': 'таблица указателей в данных',
        'prologue': 'пролог ST RP / ENTER (проверена вся цепочка)',
        'gapstart': 'начало сразу после конца другой функции (проверено)'}
for k, v in summ['sources'].items():
    P(f'| {k} | {expl.get(k, "")} | {v} |')

# regions: 64 KiB buckets
P('\n## Распределение кода по образу (блоки 64 КиБ)\n')
P('| Смещение файла | CPU | Функций | Байт кода | Доля FF |\n|---|---|---:|---:|---:|')
fb = Counter()
bb = Counter()
for r in rows:
    if not r['file_off']:
        continue
    o = int(r['file_off'], 16)
    fb[o >> 16] += 1
    bb[o >> 16] += int(r['bytes'])
for blk in range(0, (len(data) + 0xFFFF) >> 16):
    seg = data[blk << 16:(blk + 1) << 16]
    ff = seg.count(0xFF) / max(1, len(seg))
    if fb[blk] or ff < 0.99:
        P(f'| 0x{blk << 16:06x} | 0x{(blk << 16) + base:06x} | {fb[blk]} | {bb[blk]} | {ff:.2f} |')

P('\n## Самые вызываемые функции\n')
P('| Адрес | Вызывающих | Инструкций | Вызовы ОС | Имя (атлас) |\n|---|---:|---:|---|---|')
for r in sorted(rows, key=lambda r: -int(r['callers']))[:40]:
    P(f"| {r['entry']} | {r['callers']} | {r['insns']} | {r['os_ints']} | {r['name']} |")

P('\n## Системные вызовы (INT 0x40, код в r12)\n')
P('| Код | Функций-пользователей | Пример |\n|---|---:|---|')
for k, v in list(osc.items())[:60]:
    P(f'| {k} | {len(v)} | {" ".join(v[:4])} |')

P('\n## Самые используемые адреса памяти/периферии\n')
P('Адрес известен, если базовый регистр загружен константой в том же блоке. '
  'R/W/M — чтение/запись/чтение-модификация-запись, число — разрядность.\n')
mem = xr['memory']
items = []
for a, kinds in mem.items():
    fs = set()
    for v in kinds.values():
        fs.update(v)
    items.append((len(fs), a, kinds))
items.sort(reverse=True)


def region(a):
    a = int(a, 16)
    if a < 0x400:
        return 'I/O (прямая)'
    if a < 0x1000:
        return 'I/O регистры'
    if 0x40000000 <= a < 0x50000000:
        return 'периферия/ASIC'
    if 0x80000000 <= a < 0x90000000:
        return 'RAM (SDRAM)'
    if base <= a < base + len(data):
        return 'ROM'
    return 'прочее'


P('| Адрес | Область | Функций | Доступ |\n|---|---|---:|---|')
for n, a, kinds in items[:60]:
    P(f'| {a} | {region(a)} | {n} | {" ".join(sorted(kinds))} |')

regc = Counter(region(a) for a in mem)
P('\nАдресов по областям: ' + ', '.join(f'{k}: {v}' for k, v in regc.most_common()) + '\n')

P('## Периферия: группы регистров (по 256 байт)\n')
grp = defaultdict(set)
for a, kinds in mem.items():
    ai = int(a, 16)
    if region(a) in ('I/O регистры', 'периферия/ASIC', 'I/O (прямая)'):
        for v in kinds.values():
            grp[ai & ~0xFF].update(v)
for a, kinds in xr['direct_io'].items():
    for v in kinds.values():
        grp[int(a, 16) & ~0xFF].update(v)
P('| База | Функций | Примеры функций |\n|---|---:|---|')
for g, fs in sorted(grp.items(), key=lambda kv: -len(kv[1]))[:40]:
    P(f'| 0x{g:08x} | {len(fs)} | {" ".join(sorted(fs)[:5])} |')

P('\n## Строки, на которые ссылается код\n')
P('| CPU | Текст | Функции |\n|---|---|---|')
k = 0
for s in strs:
    if s['referencing_functions']:
        t = s['text'].replace('|', '\\|')[:60]
        P(f"| {s['cpu']} | `{t}` | {s['referencing_functions'][:60]} |")
        k += 1
P(f'\nВсего строк со ссылками: {k} из {len(strs)}.')
