# Карта функций части B (BD400111.bin)

Сгенерировано `tools/frdis/analyze.py` + `report.py`. Статический анализ, без исполнения; назначения — по данным, а не по документации Nikon.

## Итог

| Показатель | Значение |
|---|---:|
| Функций | 5039 |
| Инструкций | 324084 |
| Байт кода покрыто | 789956 |
| Размер образа | 3997696 |
| Функций с ошибкой декодирования | 0 |
| Неразрешённых косвенных переходов | 247 |
| Адресов памяти с известным обращением | 4090 |
| Адресов прямой адресации I/O | 83 |
| ASCII-строк | 806 |

Источник обнаружения функций (функция может иметь несколько):

| Источник | Смысл | Кол-во |
|---|---|---:|
| vector | таблица векторов | 44 |
| call | цель прямого/разрешённого вызова | 2206 |
| tailjmp | хвостовой переход | 1002 |
| atlas | адрес из атласа v15 | 89 |
| constptr | константа-указатель в коде | 71 |
| ptrtable | таблица указателей в данных | 98 |
| prologue | пролог ST RP / ENTER (проверена вся цепочка) | 1439 |
| gapstart | начало сразу после конца другой функции (проверено) | 209 |

## Распределение кода по образу (блоки 64 КиБ)

| Смещение файла | CPU | Функций | Байт кода | Доля FF |
|---|---|---:|---:|---:|
| 0x000000 | 0x040000 | 528 | 73714 | 0.01 |
| 0x010000 | 0x050000 | 453 | 69030 | 0.01 |
| 0x020000 | 0x060000 | 450 | 76082 | 0.01 |
| 0x030000 | 0x070000 | 467 | 77038 | 0.01 |
| 0x040000 | 0x080000 | 384 | 79768 | 0.01 |
| 0x050000 | 0x090000 | 378 | 65084 | 0.01 |
| 0x060000 | 0x0a0000 | 384 | 68348 | 0.01 |
| 0x070000 | 0x0b0000 | 398 | 82598 | 0.00 |
| 0x080000 | 0x0c0000 | 100 | 9744 | 0.05 |
| 0x090000 | 0x0d0000 | 2 | 2228 | 0.04 |
| 0x0a0000 | 0x0e0000 | 0 | 0 | 0.33 |
| 0x0e0000 | 0x120000 | 247 | 62160 | 0.00 |
| 0x0f0000 | 0x130000 | 323 | 66854 | 0.00 |
| 0x100000 | 0x140000 | 333 | 80870 | 0.01 |
| 0x110000 | 0x150000 | 93 | 15182 | 0.21 |
| 0x120000 | 0x160000 | 0 | 0 | 0.00 |
| 0x170000 | 0x1b0000 | 0 | 0 | 0.14 |
| 0x180000 | 0x1c0000 | 0 | 0 | 0.11 |
| 0x190000 | 0x1d0000 | 0 | 0 | 0.11 |
| 0x1a0000 | 0x1e0000 | 1 | 1362 | 0.09 |
| 0x1b0000 | 0x1f0000 | 0 | 0 | 0.07 |
| 0x1c0000 | 0x200000 | 0 | 0 | 0.07 |
| 0x1d0000 | 0x210000 | 7 | 704 | 0.09 |
| 0x1e0000 | 0x220000 | 2 | 20 | 0.17 |
| 0x1f0000 | 0x230000 | 0 | 0 | 0.15 |
| 0x200000 | 0x240000 | 0 | 0 | 0.14 |
| 0x210000 | 0x250000 | 0 | 0 | 0.18 |
| 0x220000 | 0x260000 | 1 | 168 | 0.16 |
| 0x230000 | 0x270000 | 24 | 45694 | 0.04 |
| 0x240000 | 0x280000 | 2 | 64 | 0.04 |
| 0x250000 | 0x290000 | 0 | 0 | 0.00 |
| 0x260000 | 0x2a0000 | 1 | 2052 | 0.00 |
| 0x270000 | 0x2b0000 | 0 | 0 | 0.00 |
| 0x280000 | 0x2c0000 | 2 | 194 | 0.00 |
| 0x290000 | 0x2d0000 | 4 | 230 | 0.00 |
| 0x2a0000 | 0x2e0000 | 0 | 0 | 0.00 |
| 0x2b0000 | 0x2f0000 | 0 | 0 | 0.00 |
| 0x2c0000 | 0x300000 | 2 | 116 | 0.00 |
| 0x2d0000 | 0x310000 | 118 | 39884 | 0.00 |
| 0x2e0000 | 0x320000 | 71 | 25122 | 0.12 |
| 0x2f0000 | 0x330000 | 0 | 0 | 0.00 |
| 0x300000 | 0x340000 | 0 | 0 | 0.00 |
| 0x310000 | 0x350000 | 0 | 0 | 0.01 |
| 0x320000 | 0x360000 | 2 | 38 | 0.01 |
| 0x330000 | 0x370000 | 0 | 0 | 0.01 |
| 0x340000 | 0x380000 | 0 | 0 | 0.01 |
| 0x350000 | 0x390000 | 203 | 50144 | 0.00 |
| 0x360000 | 0x3a0000 | 59 | 12424 | 0.01 |
| 0x370000 | 0x3b0000 | 0 | 0 | 0.00 |
| 0x380000 | 0x3c0000 | 0 | 0 | 0.01 |
| 0x390000 | 0x3d0000 | 0 | 0 | 0.01 |
| 0x3a0000 | 0x3e0000 | 0 | 0 | 0.60 |

## Самые вызываемые функции

| Адрес | Вызывающих | Инструкций | Вызовы ОС | Имя (атлас) |
|---|---:|---:|---|---|
| 0x44c26 | 217 | 28 | 40:-24*1 40:-27*2 40:-55*1 |  |
| 0x44be8 | 211 | 29 | 40:-24*1 40:-27*2 40:-53*1 |  |
| 0x88c30 | 189 | 17 |  |  |
| 0x890c6 | 178 | 115 |  |  |
| 0x7d72a | 158 | 84 |  |  |
| 0x883d8 | 157 | 34 | 40:-48*1 |  |
| 0x7b7b6 | 141 | 54 |  |  |
| 0x8837c | 141 | 6 |  |  |
| 0xa9a50 | 126 | 42 | 40:-48*1 40:-53*1 40:-55*1 | enqueue_state_action |
| 0x4c1c2 | 124 | 8 |  |  |
| 0x6a636 | 114 | 37 | 40:-170*1 40:-47*2 |  |
| 0xbe78c | 107 | 39 |  |  |
| 0x4e734 | 94 | 39 | 40:-107*2 |  |
| 0x79870 | 85 | 35 | 40:-53*1 40:-55*2 |  |
| 0xbeb96 | 82 | 36 |  |  |
| 0x885aa | 74 | 61 |  |  |
| 0x73322 | 73 | 1 |  |  |
| 0x4e882 | 64 | 125 |  |  |
| 0xbefc0 | 63 | 26 |  |  |
| 0x7982e | 61 | 32 | 40:-53*1 40:-55*2 |  |
| 0x3a0a3a | 60 | 79 |  |  |
| 0x44b8a | 56 | 8 |  |  |
| 0x6012e | 56 | 30 |  |  |
| 0x89af0 | 55 | 16 | 40:-48*1 |  |
| 0x132286 | 52 | 126 |  |  |
| 0x89ace | 49 | 14 | 40:-47*1 |  |
| 0x44bd0 | 48 | 12 |  |  |
| 0x4e866 | 48 | 8 |  |  |
| 0x3a12da | 46 | 21 |  |  |
| 0x9aacc | 45 | 5 |  |  |
| 0x57a9e | 44 | 24 |  |  |
| 0xbec7a | 44 | 36 |  |  |
| 0x44b7e | 43 | 7 |  |  |
| 0x88df6 | 42 | 24 |  |  |
| 0xbe982 | 42 | 39 |  |  |
| 0x73336 | 41 | 7 |  |  |
| 0x138546 | 41 | 23 | 40:-47*1 40:-48*1 |  |
| 0x1485d8 | 40 | 232 |  |  |
| 0x57a1e | 39 | 41 |  |  |
| 0x41b26 | 38 | 10 |  |  |

## Системные вызовы (INT 0x40, код в r12)

| Код | Функций-пользователей | Пример |
|---|---:|---|
| 40:-48 | 402 | 0x123672 0x123860 0x123ad0 0x123e20 |
| 40:-47 | 285 | 0x12337e 0x128dd4 0x132c3e 0x135570 |
| 40:-46 | 154 | 0x12337e 0x14d5d8 0x39da76 0x39db1a |
| 40:-55 | 80 | 0x14d5d8 0x40000 0x40064 0x4008e |
| 40:-53 | 71 | 0x14d5d8 0x40000 0x40064 0x4008e |
| 40:-170 | 68 | 0x132c3e 0x13d240 0x140bb2 0x140c90 |
| 40:-37 | 64 | 0x13099a 0x1309d8 0x1324e2 0x138d44 |
| 40:-85 | 40 | 0x13cf26 0x13cfec 0x142752 0x142916 |
| 40:-24 | 26 | 0x44be8 0x44c26 0x4b260 0x4f434 |
| 40:-23 | 23 | 0x1234ae 0x14d47a 0x14dfa8 0x14e14c |
| 40:-106 | 19 | 0x14dd02 0x4dea4 0x70560 0x774b6 |
| 40:-20 | 12 | 0x123672 0x14d5d8 0x40730 0x45eb8 |
| 40:-8 | 10 | 0x15cb6c 0x15cbe4 0x15d016 0x15d0fc |
| 40:-7 | 7 | 0x15cb6c 0x15d016 0x15d0fc 0x40384 |
| 40:-27 | 7 | 0x14dd02 0x400f2 0x44be8 0x44c26 |
| 64 | 7 | 0x13ce8e 0x15047e 0x41f80 0x42244 |
| 40:-25 | 6 | 0x123672 0x14d5d8 0x898dc 0x8be72 |
| 0 | 5 | 0x1e0000 0x218fe2 0x219302 0x272052 |
| 40:-38 | 5 | 0x12c734 0x14243a 0x142534 0x1500ea |
| 40:-21 | 4 | 0x48400 0x48466 0x9343e 0xaa1ec |
| 40:-107 | 4 | 0x45eb8 0x4e734 0x8c18c 0x8c1c8 |
| 40:-171 | 2 | 0x4e7ae 0x8c206 |
| 40:-52 | 2 | 0x4e830 0x8c390 |
| 31 | 2 | 0x1e0000 0x272052 |
| 40:-31 | 1 | 0x4edd2 |
| 40:-83 | 1 | 0x407ca |
| 30 | 1 | 0xd8cac |
| 62 | 1 | 0x1e0000 |
| 60 | 1 | 0x1e0000 |
| 3 | 1 | 0x1e0000 |
| 7 | 1 | 0x1e0000 |
| 104 | 1 | 0xc1542 |
| 164 | 1 | 0xc1542 |
| 8 | 1 | 0xc1542 |
| 32 | 1 | 0x27af50 |
| 15 | 1 | 0x285db2 |
| 170 | 1 | 0x3102ce |
| 40:-28 | 1 | 0x44cac |

## Самые используемые адреса памяти/периферии

Адрес известен, если базовый регистр загружен константой в том же блоке. R/W/M — чтение/запись/чтение-модификация-запись, число — разрядность.

| Адрес | Область | Функций | Доступ |
|---|---|---:|---|
| 0x83cee49c | RAM (SDRAM) | 228 | M32 W32 |
| 0x44c26 | ROM | 217 | M32 |
| 0x44be8 | ROM | 211 | M32 |
| 0x88c30 | ROM | 186 | M32 |
| 0x890c6 | ROM | 177 | M32 |
| 0x883d8 | ROM | 157 | M32 |
| 0x7d72a | ROM | 154 | M32 |
| 0x8837c | ROM | 141 | M32 |
| 0x7b7b6 | ROM | 141 | M32 |
| 0x83cea3c5 | RAM (SDRAM) | 128 | M16 M32 |
| 0x4c1c2 | ROM | 124 | M32 |
| 0xa9a50 | ROM | 123 | M32 |
| 0x6a636 | ROM | 114 | M32 |
| 0xbe78c | ROM | 107 | M32 |
| 0x4e734 | ROM | 94 | M32 |
| 0x79870 | ROM | 85 | M32 |
| 0xbeb96 | ROM | 82 | M32 |
| 0x885aa | ROM | 74 | M32 |
| 0x83ce971e | RAM (SDRAM) | 72 | M16 M32 R8 |
| 0x83ce9716 | RAM (SDRAM) | 70 | M16 M32 |
| 0x83ced610 | RAM (SDRAM) | 66 | M32 |
| 0x4e882 | ROM | 64 | M32 |
| 0xbefc0 | ROM | 63 | M32 |
| 0x83cee4c0 | RAM (SDRAM) | 62 | R8 W8 |
| 0x7982e | ROM | 60 | M32 |
| 0x3a0a3a | ROM | 60 | M32 |
| 0x73322 | ROM | 56 | M32 |
| 0x44b8a | ROM | 56 | M32 |
| 0x89af0 | ROM | 55 | M32 |
| 0x83ce98f4 | RAM (SDRAM) | 52 | M16 M32 W32 |
| 0x6012e | ROM | 51 | M32 |
| 0x132286 | ROM | 51 | M32 |
| 0x89ace | ROM | 49 | M32 |
| 0x4e866 | ROM | 48 | M32 |
| 0x44bd0 | ROM | 48 | M32 |
| 0x83cee4c1 | RAM (SDRAM) | 47 | M16 M32 R8 |
| 0x68000ab0 | прочее | 47 | M32 W32 |
| 0x3a12da | ROM | 46 | M32 |
| 0xbec7a | ROM | 44 | M32 |
| 0x9aacc | ROM | 44 | M32 |
| 0x83cee4bf | RAM (SDRAM) | 44 | R8 |
| 0x44b7e | ROM | 43 | M32 |
| 0xbe982 | ROM | 42 | M32 |
| 0x83ced238 | RAM (SDRAM) | 42 | M16 M32 R16 R8 W16 |
| 0x83ced108 | RAM (SDRAM) | 42 | M32 |
| 0x57a9e | ROM | 41 | M32 |
| 0x1485d8 | ROM | 40 | M32 |
| 0x83ced23a | RAM (SDRAM) | 39 | R16 W16 |
| 0x88df6 | ROM | 38 | M32 |
| 0x73336 | ROM | 38 | M32 |
| 0x4f704 | ROM | 38 | M32 |
| 0x41b26 | ROM | 38 | M32 |
| 0x83ce9551 | RAM (SDRAM) | 37 | M16 M32 R8 |
| 0x83ce950c | RAM (SDRAM) | 37 | M16 R8 |
| 0x7bbda | ROM | 37 | M32 |
| 0x57a1e | ROM | 37 | M32 |
| 0xbefe2 | ROM | 36 | M32 |
| 0x4f742 | ROM | 36 | M32 |
| 0x43dfe | ROM | 36 | M32 |
| 0x14c166 | ROM | 36 | M32 |

Адресов по областям: ROM: 2701, RAM (SDRAM): 1174, прочее: 116, периферия/ASIC: 49, I/O регистры: 30, I/O (прямая): 20

## Периферия: группы регистров (по 256 байт)

| База | Функций | Примеры функций |
|---|---:|---|
| 0x00000000 | 80 | 0x1e0000 0x26358e 0x272052 0x27af50 0x27c0aa |
| 0x00000100 | 23 | 0x27af50 0x27c0aa 0x27ca0e 0x27cc48 0x27cc4a |
| 0x00000300 | 22 | 0x27af50 0x27ca0e 0x27cc48 0x27cc4a 0x27cc4c |
| 0x40020000 | 18 | 0x40b18 0x494f2 0x4c086 0x5b140 0x60172 |
| 0x00000400 | 10 | 0x407f2 0x478d2 0x89b16 0x89cce 0x89ddc |
| 0x00000200 | 6 | 0x2d50b8 0x30fabe 0x310000 0x31121c 0x3125a2 |
| 0x40060000 | 5 | 0x15d3d4 0x40ba2 0x69b24 0x6a212 0x83ce8ec0 |
| 0x400e0000 | 5 | 0x40b18 0x658b0 0x65a7e 0x689c0 0x68bbc |
| 0x40040000 | 4 | 0x15d3d4 0x69b24 0x6a212 0x83ce8ec0 |
| 0x40090000 | 4 | 0x40b18 0x47840 0x49656 0x49760 |
| 0x00000d00 | 3 | 0x8bd38 0x9989e 0x999b4 |
| 0x40030000 | 3 | 0x49f74 0x690a4 0x6924e |
| 0x40070000 | 3 | 0xc0f90 0xc1358 0xc13b0 |
| 0x400a0000 | 3 | 0x40b18 0x491aa 0x49352 |
| 0x40000000 | 2 | 0x46044 0x4620a |
| 0x40010000 | 2 | 0x40b18 0x4b260 |
| 0x4001ff00 | 2 | 0x40ba2 0x4c0b0 |
| 0x40092000 | 2 | 0x4984a 0x49882 |
| 0x400d0000 | 2 | 0x40b18 0x478aa |
| 0x00000600 | 1 | 0xc0f90 |
| 0x40008000 | 1 | 0x40ba2 |
| 0x40009000 | 1 | 0x40ba2 |
| 0x4000a000 | 1 | 0x40ba2 |
| 0x4000b000 | 1 | 0x40ba2 |
| 0x4000c000 | 1 | 0x46044 |
| 0x4000d000 | 1 | 0x46044 |
| 0x40021000 | 1 | 0x40ba2 |
| 0x40030100 | 1 | 0x4a086 |
| 0x40030400 | 1 | 0x40b18 |
| 0x40040300 | 1 | 0xaba80 |
| 0x40080000 | 1 | 0x40b18 |
| 0x400a0f00 | 1 | 0x40ba2 |

## Строки, на которые ссылается код

| CPU | Текст | Функции |
|---|---|---|
| 0xc6030 | `Optional` | 0x47c1a |
| 0xceb04 | `NIKON D40` | 0x59136 |
| 0xceb10 | `NIKON D40` | 0x590e4 |
| 0xceb1c | `BLACK AND WHITE` | 0x5904c |
| 0xceb2c | `Nikon` | 0x589e8 |
| 0xceb34 | `NIKON D40` | 0x589e8 |
| 0xceb40 | `NIKON` | 0x589e8 |
| 0xceb48 | `Nikon` | 0x5864c |
| 0xceb50 | `NIKON D40` | 0x5864c |
| 0xceb5c | `NIKON` | 0x5864c |
| 0xceb74 | `ASCII` | 0x572be |
| 0xcec1c | `AUTO           ` | 0x56e82 |
| 0xcec2c | `MODERATE       ` | 0x56e82 |
| 0xcec3c | `ENHANCED       ` | 0x56e82 |
| 0xcec4c | `BLACK AND WHITE` | 0x56d16 |
| 0xcec5c | `CUSTOM         ` | 0x56d16 |
| 0xcec6c | `SOFT           ` | 0x56d16 |
| 0xcec7c | `PORTRAIT       ` | 0x56d16 |
| 0xcec8c | `MORE VIVID     ` | 0x56d16 |
| 0xcec9c | `VIVID          ` | 0x56d16 |
| 0xcecac | `MIXED      ` | 0x56802 |
| 0xcecb8 | `SPEEDLIGHT ` | 0x56802 |
| 0xcecc4 | `NORMAL     ` | 0x56802 |
| 0xcecd0 | `COLORED    ` | 0x56802 |
| 0xcecdc | `NATURAL    ` | 0x56802 |
| 0xcece8 | `RAW    ` | 0x5658a |
| 0xcecf0 | `BASIC  ` | 0x5658a |
| 0xcecf8 | `NORMAL ` | 0x5658a |
| 0xced00 | `FINE   ` | 0x5658a |
| 0xced08 | `MODE3a  ` | 0x561dc |
| 0xced14 | `MODE2   ` | 0x561dc |
| 0xced20 | `MODE1a  ` | 0x561dc |
| 0xced2c | `REAR SLOW   ` | 0x56050 |
| 0xced3c | `RED-EYE SLOW` | 0x56050 |
| 0xced4c | `RED-EYE     ` | 0x56050 |
| 0xced5c | `REAR        ` | 0x56050 |
| 0xced6c | `SLOW        ` | 0x56050 |
| 0xced7c | `NORMAL      ` | 0x56050 |
| 0xced8c | `AF-A  ` | 0x55f60 |
| 0xced94 | `AF-C  ` | 0x55f60 |
| 0xced9c | `AF-S  ` | 0x55f60 |
| 0xceda4 | `MANUAL` | 0x55f60 |
| 0xcedac | `CS      ` | 0x55bce |
| 0xcedb8 | `MED.H   ` | 0x55bce |
| 0xcedc4 | `MED.L   ` | 0x55bce |
| 0xcedd0 | `HIGH    ` | 0x55bce |
| 0xceddc | `LOW     ` | 0x55bce |
| 0xcede8 | `NORMAL  ` | 0x55bce |
| 0xcedf4 | `AUTO    ` | 0x55bce |
| 0xcee00 | `NONE  ` | 0x559ce |
| 0xcee08 | `MED.H ` | 0x559ce |
| 0xcee10 | `HIGH  ` | 0x559ce |
| 0xcee18 | `MED.L ` | 0x559ce |
| 0xcee20 | `LOW   ` | 0x559ce |
| 0xcee28 | `NORMAL` | 0x559ce |
| 0xcee30 | `AUTO  ` | 0x559ce |
| 0xcee38 | `PRESET` | 0x5579a |
| 0xcee40 | `SHADE       ` | 0x5579a |
| 0xcee50 | `CLOUDY      ` | 0x5579a |
| 0xcee60 | `FLASH       ` | 0x5579a |
| 0xcee70 | `SUNNY       ` | 0x5579a |
| 0xcee80 | `FLUORESCENT ` | 0x5579a |
| 0xcee90 | `INCANDESCENT` | 0x5579a |
| 0xceea0 | `AUTO        ` | 0x5579a |
| 0xceeb0 | `UNKNOWN` | 0x5525e |
| 0xceeb8 | `UNKNOWN` | 0x5525e |
| 0xceecc | `B & W          ` | 0x55176 |
| 0xceedc | `BLACK AND WHITE` | 0x55176 |
| 0xceef0 | `ASCII` | 0x54d14 |
| 0xcef04 | `COOL ` | 0x5479a |
| 0xcef0c | `SEPIA` | 0x5479a |
| 0xcef14 | `COLOR` | 0x5479a |
| 0xcef1c | `Nikon` | 0x542cc |
| 0xcef24 | `Nikon` | 0x53c84 |
| 0xcef2c | `Nikon` | 0x53aa6 |
| 0xcef34 | `Nikon` | 0x53810 |
| 0xcef3c | `Nikon` | 0x532a8 |
| 0xcef58 | `Nikon` | 0x52eb6 |
| 0xcef60 | `NIKON` | 0x52eb6 |
| 0xcef68 | `Nikon` | 0x52864 |
| 0xcef70 | `Nikon` | 0x524c8 |
| 0xcef78 | `Nikon` | 0x5221e |
| 0xcef80 | `Nikon` | 0x51ce4 |
| 0xcef88 | `Nikon` | 0x5191e |
| 0xcef90 | `Nikon` | 0x51634 |
| 0xcef98 | `Nikon` | 0x5136e |
| 0xcefa0 | `Nikon` | 0x50de4 |
| 0xcefa8 | `Nikon` | 0x50b34 |
| 0xcefb0 | `Nikon` | 0x506ea |
| 0xcefb8 | `NIKON D40` | 0x4fe7a |
| 0xcefc4 | `NIKON CORPORATION` | 0x4fe7a |
| 0xcefe0 | `SMALL PICTURE` | 0x4fa7c |
| 0xcfa34 | `NORMAL` | 0x62ffc |
| 0xcfa3c | `NORMAL` | 0x62ffc |
| 0xcfa60 | `BASIC` | 0x62ffc |
| 0xcfa9c | `NIKON D40` | 0x62ffc |
| 0xcfaa8 | `NIKON CORPORATION` | 0x62ffc |
| 0xd4896 | `sssssssssssssssssssssssstttttttttttttttttttttttttttttttttttt` | 0x65e0c 0x66cae |
| 0xd4b96 | `mmmmmmmmmmmmmmmmmmmllllllllllllllllllllllllllllllllkkkkkkkkk` | 0x65e0c 0x66cae |
| 0xd4e96 | `fffffffffeeeeeeeeeeeeedddddddddddddddccccccccccccccccccbbbbb` | 0x65e0c 0x66cae |
| 0xd5314 | `"!!!#(` | 0x6a806 0x6a8e8 |
| 0xd534c | `NIKOND40_WP_USER` | 0x15cbe4 0x83ce86ce |
| 0xd5468 | `CF_GetFreeSpace` | 0x6c756 |
| 0xd5478 | `CF_closedir` | 0x6c712 |
| 0xd5484 | `CF_readdir` | 0x6c6ca |
| 0xd5490 | `CF_opendir` | 0x6c688 |
| 0xd549c | `CF_rmdir` | 0x6c646 |
| 0xd54a8 | `CF_mkdir` | 0x6c5ec |
| 0xd54b4 | `CF_SetFattr` | 0x6c5aa |
| 0xd54c0 | `CF_GetFattr` | 0x6c55c |
| 0xd54cc | `CF_stat` | 0x6c51a |
| 0xd54d4 | `CF_remove` | 0x6c4d8 |
| 0xd54e0 | `CF_rename` | 0x6c496 |
| 0xd54ec | `CF_create` | 0x6c44e |
| 0xd54f8 | `CF_write` | 0x6c360 |
| 0xd5504 | `CF_read` | 0x6c2e2 |
| 0xd550c | `CF_close` | 0x6c2a0 |
| 0xd5518 | `CF_open` | 0x6c25e |
| 0xd5568 | `NIKON D40` | 0x6ca34 |
| 0xd5574 | `NIKON CORPORATION` | 0x6ca34 |
| 0xd5890 | `NCD40` | 0x72f52 |
| 0xd5898 | `NCD40` | 0x72f52 |
| 0xd58a0 | `NCD40` | 0x72f52 |
| 0xd58a8 | `A:\DCIM\` | 0x72728 |
| 0xd58b4 | `A:\DCIM\` | 0x72528 |
| 0xd58c0 | `A:\DCIM\` | 0x72528 |
| 0xd58cc | `NCD40` | 0x723b0 |
| 0xd58d4 | `A:\DCIM` | 0x71f9a |
| 0xd58dc | `A:\DCIM` | 0x71f9a |
| 0xd58e4 | `A:\DCIM` | 0x71f9a |
| 0xd58ec | `NCD40` | 0x71f9a |
| 0xd58f4 | `NCD40` | 0x71f9a |
| 0xd58fc | `A:\DCIM` | 0x715e0 |
| 0xd5904 | `NCD40` | 0x71234 |
| 0xd590c | `A:\DCIM` | 0x71234 |
| 0xd5914 | `A:\DCIM` | 0x71234 |
| 0xd591c | `A:\DCIM` | 0x71234 |
| 0xd5938 | `A:\DCIM` | 0x70010 |
| 0xd5940 | `A:\DCIM` | 0x70010 |
| 0xd5948 | `A:\DCIM` | 0x70010 |
| 0xd5950 | `A:\DCIM` | 0x6fd14 |
| 0xd5958 | `A:\DCIM` | 0x6fd14 |
| 0xd5960 | `A:\DCIM.` | 0x6fd14 |
| 0xd596c | `A:\DCIM\` | 0x6f834 |
| 0xd5978 | `A:\DCIM\` | 0x6e014 |
| 0xd5984 | `A:\DCIM` | 0x6db84 0x6dd2c |
| 0xd598c | `A:\DCIM` | 0x6db84 |
| 0xd5994 | `A:\DCIM` | 0x6db84 |
| 0xd599c | `A:\DCIM` | 0x6db84 |
| 0xd5be8 | `               ` | 0x7665c |
| 0xd5cb0 | `NORMAL         ` | 0x764c6 |
| 0xd5d30 | `               ` | 0x764c6 |
| 0xd5d8c | `MODE3a  ` | 0x75aae |
| 0xd5d98 | `MODE2   ` | 0x75aae |
| 0xd5da4 | `MODE1a  ` | 0x75aae |
| 0xd5ebc | `BASIC` | 0x74b90 |
| 0xd5ec4 | `NORMAL` | 0x74b90 |
| 0xd5ed8 | `B & W` | 0x74a94 |
| 0xd5ee8 | `SEPIA` | 0x74a94 |
| 0xd5ef0 | `B & W` | 0x74a94 |
| 0xd5ef8 | `COLOR` | 0x74a94 |
| 0xd5f18 | `NIKON D40` | 0x735e8 |
| 0xd5f24 | `NIKON CORPORATION` | 0x7358a |
| 0xd6878 | `Nikon` | 0x76c7c 0x76e88 |
| 0xd68a4 | `ASCII` | 0x741f8 |
| 0xd68cc | `010201080109010001000102020202080209` | 0x75ff4 |
| 0xd79dc | `NIKON D40` | 0x79084 |
| 0xd79f4 | `NIKON D40` | 0x78f04 |
| 0xd7a64 | `IMG SRC` | 0x7a862 |
| 0xd7a6c | `-ATR CMT` | 0x7a862 |
| 0xd7a78 | `-ATR DTM` | 0x7a862 |
| 0xd7a8c | `/DCIM/` | 0x7a162 0x7a196 |
| 0xd7d84 | `NIKON D40` | 0x12196c |
| 0xd8cbc | `NCD40` | 0x14027c |
| 0xd8cc4 | `NCD40` | 0x13fb32 0x13fb4e |
| 0xd8ccc | `NCD40` | 0x13fb32 0x13fb4e |
| 0xd8cd4 | `NCD40` | 0x13fb32 0x13fb4e |
| 0xd8cdc | `NCD40` | 0x13f96a 0x13f9a4 |
| 0xd8ce4 | `NCD40` | 0x13f96a 0x13f9a4 |
| 0xd8cec | `NCD40` | 0x13f96a 0x13f9a4 |
| 0xd8cf4 | `NCD40` | 0x13f8c4 |
| 0xd9728 | `NCD40` | 0x14a32c |
| 0xd9875 | `0123456789` | 0x14c190 |
| 0xd98b5 | ` !"#$%&'()*+,-.` | 0x14b7da |
| 0xd9c54 | `AUTPRINT.MRK` | 0x87916 |
| 0xd9c78 | `DSC_0001.` | 0x87916 |
| 0xd9c84 | `DSC_0002.` | 0x87916 |
| 0xd9ca4 | `A:\MISC\AUTPRINT.MRK` | 0x86de2 |
| 0xd9cbc | `A:\MISC` | 0x86de2 |
| 0xd9cc4 | `A:\DCIM` | 0x86de2 |
| 0xd9ccc | `A:\MISC\AUTPRINT.MRK` | 0x80664 0x80a16 |
| 0xd9ce4 | `A:\MISC` | 0x80664 0x80a16 |
| 0xd9cec | `A:\DCIM` | 0x80664 0x80a16 |
| 0xd9d00 | `Nikon Corporation` | 0x7fc26 |
| 0xd9d14 | `microsoft.com: 1.0` | 0x7fc26 |
| 0xda3b4 | `NCD40` | 0x9121c |
| 0xda3bc | `NCD40` | 0x9121c |
| 0xda3c4 | `NCD40` | 0x9121c |
| 0xdb0d6 | `HT`lx` | 0x39693a 0x396946 |
| 0xddd46 | `       /       ` | 0x150326 |
| 0xdddb8 | `Nikon Corporation` | 0x940a2 |
| 0xde0f4 | `FAT32   ` | 0x9755a |
| 0xde100 | `NO NAME    ` | 0x9755a |
| 0xde10c | `        ` | 0x9755a |
| 0xde118 | `FAT16   ` | 0x968be 0x96d4a |
| 0xde124 | `FAT12   ` | 0x968be 0x96d4a |
| 0xde130 | `        ` | 0x95eee |
| 0xde13c | `FAT16   ` | 0x95eee |
| 0xde148 | `FAT12   ` | 0x95eee |
| 0xde154 | `NO NAME    ` | 0x95eee |
| 0xde160 | `MSDOS5.0` | 0x95eee |
| 0xe21de | `HLPTX\`dhlptxHT`lx` | 0xa296c |
| 0xe480c | `END OF Q330 CONFIG` | 0xa923c |
| 0xe4b9c | `NIKOND40_WP_USERA:\` | 0xab3da |
| 0xe4bb8 | `AD40????.BIN` | 0xab5cc |
| 0xe4bc8 | `BD40????.BIN` | 0xab5cc |
| 0xe4d5c | `output` | 0xabfa2 |
| 0xe4d64 | `continueJob` | 0xabfa2 |
| 0xe4d70 | `abortJob` | 0xabfa2 |
| 0xe4d7c | `startJob` | 0xabfa2 |
| 0xe4d88 | `getDeviceStatus` | 0xabfa2 |
| 0xe4d98 | `getJobStatus` | 0xabfa2 |
| 0xe4da8 | `getCapability` | 0xabfa2 |
| 0xe4db8 | `configurePrintService` | 0xabfa2 |
| 0xe4dd0 | `result` | 0xabfa2 |
| 0xe4dd8 | `result` | 0xabfa2 |
| 0xe4de0 | `output` | 0xabfa2 |
| 0xe4de8 | `input` | 0xabfa2 |
| 0xe4df0 | `notifyDeviceStatus` | 0xabfa2 |
| 0xe4e04 | `notifyJobStatus` | 0xabfa2 |
| 0xe4e14 | `input` | 0xabfa2 |
| 0xe4e98 | `serialNo` | 0xac4b8 0xac4f8 |
| 0xe4ea4 | `productName` | 0xac4b8 0xac4f8 |
| 0xe4eb0 | `vendorSpecificVersion` | 0xac4b8 0xac4f8 |
| 0xe4ec8 | `vendorName` | 0xac4b8 0xac4f8 |
| 0xe4ed4 | `dpsVersions` | 0xac4b8 0xac4f8 |
| 0xe4ee0 | `printServiceAvailable` | 0xac4b8 0xac4f8 |
| 0xe4ef8 | `</configurePrintService>` | 0xac338 |
| 0xe4f14 | `serialNo` | 0xac338 |
| 0xe4f20 | `productName` | 0xac338 |
| 0xe4f2c | `vendorSpecificVersion` | 0xac338 |
| 0xe4f44 | `vendorName` | 0xac338 |
| 0xe4f50 | `</dpsVersions>` | 0xac338 |
| 0xe4f64 | `<dpsVersions>` | 0xac338 |
| 0xe4f74 | `<configurePrintService>` | 0xac338 |
| 0xe4f8c | `<continueJob/>` | 0xac722 |
| 0xe4f9c | `capability` | 0xac8b6 |
| 0xe4fa8 | `paperSize` | 0xac8b6 |
| 0xe4fb4 | `capability` | 0xac8b6 |
| 0xe5138 | `<getDeviceStatus/>` | 0xaca6e |
| 0xe514c | `imagesPrinted` | 0xacc48 0xacc92 |
| 0xe515c | `progress` | 0xacc48 0xacc92 |
| 0xe5168 | `copyID` | 0xacc48 0xacc92 |
| 0xe5170 | `filePath` | 0xacc48 0xacc92 |
| 0xe517c | `prtPID` | 0xacc48 0xacc92 |
| 0xe51a8 | `<getJobStatus/>` | 0xacbd8 |
| 0xe5330 | `"1.0"` | 0xad250 |
| 0xe533c | `version` | 0xad250 |
| 0xe5344 | `<?xml` | 0xad250 |
| 0xe5350 | `</output>` | 0xad810 |
| 0xe535c | `<output>` | 0xad800 |
| 0xe5368 | `</input>` | 0xad7f0 |
| 0xe5374 | `<input>` | 0xad7e0 |
| 0xe539c | `</dps>` | 0xad666 |
| 0xe53a4 | `<?xml version="1.0"?><dps xmlns="http://www.cipa.jp/dps/sche` | 0xad64a |
| 0xe84fc | `NO NAME    ` | 0xb8612 |
| 0xe8508 | `NO NAME    ` | 0xb8612 |
| 0xe8720 | `FAT12   ` | 0xbdef8 |
| 0xe872c | `NO NAME    ` | 0xbdef8 |
| 0xe8738 | `FAT32   ` | 0xbdb08 0xbdc98 |
| 0xe8744 | `NO NAME    ` | 0xbdb08 0xbdc98 |

Всего строк со ссылками: 271 из 806.
