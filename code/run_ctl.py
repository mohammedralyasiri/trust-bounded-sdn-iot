import sys, logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
from os_ken import cfg
from os_ken.base import app_manager
from os_ken.lib import hub

hub.patch(thread=False)
cfg.CONF(args=[], project="os_ken")
mgr = app_manager.AppManager.get_instance()
apps = sys.argv[1:] or ["os_ken.app.simple_switch_13"]
mgr.load_apps(apps)
ctx = mgr.create_contexts()
services = mgr.instantiate_apps(**ctx)
try:
    hub.joinall(services)
finally:
    mgr.close()
