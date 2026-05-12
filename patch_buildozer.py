import sys
import buildozer.targets.android as m

f = m.__file__
txt = open(f).read()

# Mostra contesto intorno a 'Detected old url/branch'
lines = txt.splitlines()
for i, line in enumerate(lines):
    if 'Detected old url/branch' in line:
        print(f'Trovato a riga {i+1}:')
        for j in range(max(0, i-5), min(len(lines), i+10)):
            print(f'  {j+1}: {repr(lines[j])}')
        break

# Patch: sostituisce l'intero blocco if che contiene 'Detected old'
# usando sostituzione testuale diretta sul blocco noto
import re

# Il blocco da sostituire (basato sul codice sorgente di buildozer 1.5.0)
patterns = [
    # Pattern con logger.info
    (
        r'([ \t]+)if any\(\[cur_url != p4a_url, cur_branch != p4a_branch\]\):[\s\S]*?buildops\.rmdir\(p4a_dir\)',
        lambda m: m.group(1) + 'if False:  # PATCH: skip reclone\n' + m.group(1) + '    pass'
    ),
    # Pattern con self.logger
    (
        r'([ \t]+)if any\(\[cur_url != p4a_url, cur_branch != p4a_branch\]\):[\s\S]*?\.rmdir\(p4a_dir\)',
        lambda m: m.group(1) + 'if False:  # PATCH: skip reclone\n' + m.group(1) + '    pass'
    ),
]

new_txt = txt
for pattern, replacement in patterns:
    result = re.sub(pattern, replacement, new_txt)
    if result != new_txt:
        new_txt = result
        print('Pattern sostituito con regex.')
        break
else:
    print('Nessun pattern regex trovato, uso metodo riga per riga...')
    # Trova la riga con 'if any' che precede 'Detected old'
    lines_list = txt.splitlines(keepends=True)
    new_lines = []
    i = 0
    while i < len(lines_list):
        line = lines_list[i]
        # Cerca il blocco 'if any([cur_url' che porta a 'Detected old'
        if 'if any(' in line and 'cur_url' in line:
            # Guarda avanti per vedere se c'e' 'Detected old'
            lookahead = ''.join(lines_list[i:i+10])
            if 'Detected old url/branch' in lookahead:
                indent = len(line) - len(line.lstrip())
                # Salta tutto il blocco if fino alla prossima riga allo stesso indent
                new_lines.append(' ' * indent + 'if False:  # PATCH: skip reclone' + chr(10))
                new_lines.append(' ' * indent + '    pass' + chr(10))
                i += 1
                while i < len(lines_list):
                    nl = lines_list[i]
                    ns = nl.lstrip()
                    ni = len(nl) - len(ns)
                    if ns and ni <= indent:
                        break
                    i += 1
                continue
        new_lines.append(line)
        i += 1
    new_txt = ''.join(new_lines)

open(f, 'w').write(new_txt)

import py_compile
try:
    py_compile.compile(f, doraise=True)
    print('Patch OK - sintassi valida')
except py_compile.PyCompileError as e:
    print(f'ERRORE SINTASSI: {e}')
    # Mostra le righe intorno all errore
    lines2 = open(f).readlines()
    import re as re2
    m2 = re2.search(r'line (\d+)', str(e))
    if m2:
        n = int(m2.group(1))
        for j in range(max(0,n-5), min(len(lines2),n+5)):
            print(f'  {j+1}: {repr(lines2[j])}')
    sys.exit(1)
