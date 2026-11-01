"""Recreate v6 tone CSV and figure. Requires matplotlib only for the figure."""
import csv
import hashlib
import sys
from pathlib import Path
from check_numeric_pipeline import words, interpolate, packed_tone, EXPECTED


def render(firmware, output):
    blob=Path(firmware).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=EXPECTED:
        raise ValueError('Unsupported firmware')
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    curves={'fallback_ROM_DC294':interpolate(words(blob,0xDC294,2048)),
            'record_0':packed_tone(blob,0),'record_13':packed_tone(blob,13),
            'record_47':packed_tone(blob,47)}
    with (out/'numeric_tone_curves.csv').open('w') as f:
        writer=csv.writer(f);writer.writerow(['LUT_index']+list(curves))
        writer.writerows([i]+[c[i] for c in curves.values()] for i in range(4096))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10})
    fig,axs=plt.subplots(1,2,figsize=(11,4.3),layout='constrained')
    colors=['#244a85','#008373','#b56a17','#a84673']
    labels=['Запасная кривая','Запись 0','Запись 13','Запись 47']
    for ax in axs:
        for values,color,label in zip(curves.values(),colors,labels):
            ax.plot(range(4096),values,color=color,label=label,lw=1.8)
        ax.grid(alpha=.2)
        ax.set_xlabel('Индекс LUT — не код сенсора')
        ax.set_ylabel('Значение элемента LUT')
    axs[0].set_title('Точные таблицы из B 1.11')
    axs[0].legend(loc='lower right',fontsize=9)
    axs[1].set_title('Участки светов');axs[1].set_xlim(3300,4095);axs[1].set_ylim(3850,4115)
    for x in (3600,3900):
        axs[1].axvline(x,color='#777777',ls=':',lw=1)
        axs[1].text(x+8,3865,str(x),rotation=90,color='#555555')
    axs[1].axhline(4095,color='#777777',ls=':',lw=.8)
    fig.savefig(out/'numeric_tone_curves.png',dpi=160);plt.close(fig)


if __name__=='__main__':
    render(sys.argv[1],sys.argv[2])
