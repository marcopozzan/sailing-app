import sys
import buildozer.targets.android as m

f = m.__file__
txt = open(f).read()

lines = txt.splitlines(keepends=True)
new_lines = []
skip = False
skip_indent = 0
for line in lines:
    stripped = line.lstrip()
    indent_len = len(line) - len(stripped)
    if 'Detected old url/branch' in line:
        skip = True
        skip_indent = indent_len
        new_lines.append(' ' * indent_len + 'pass  # PATCH: skip reclone' + chr(10))
        continue
    if skip:
        if stripped and indent_len <= skip_indent:
            skip = False
        else:
            continue
    new_lines.append(line)

result = ''.join(new_lines)
open(f, 'w').write(result)

import py_compile
try:
    py_compile.compile(f, doraise=True)
    print('Patch OK - sintassi valida')
except py_compile.PyCompileError as e:
    print(f'ERRORE SINTASSI: {e}')
    sys.exit(1)
