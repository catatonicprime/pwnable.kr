import angr

project = angr.Project('uaf', auto_load_libs=False)
cfg = project.analyses.CFGFast()

