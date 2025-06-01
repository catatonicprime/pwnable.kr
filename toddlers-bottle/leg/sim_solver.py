import angr

proj = angr.Project('a.out', load_options={'auto_load_libs': False})
proj.loader
cfg = proj.analyses.CFGEmulated()

state = proj.factory.full_init_state()
sim = proj.factory.simgr(state)
search = sim.explore(find=[0x740], avoid=[0x798])
print("Found: " + str(len(search.found)))
import code
code.interact(local=locals())
