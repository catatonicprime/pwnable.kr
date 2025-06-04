import angr

print(f'Analyzing fd')
proj = angr.Project(f'./fd', auto_load_libs=False)
proj.loader
cfg = proj.analyses.CFGEmulated()
reads = [func.calling_convention for addr, func in cfg.kb.functions.items() if 'read' == func.name]
print(reads)

for i in range(4):
    print(f'Analyzing fd{i}')
    proj = angr.Project(f'./fd{i}', auto_load_libs=False)
    proj.loader
    cfg = proj.analyses.CFGEmulated()
    reads = [func.calling_convention for addr, func in cfg.kb.functions.items() if 'read' == func.name and not func.is_plt][0]
    print(reads)
    print(type(reads))
