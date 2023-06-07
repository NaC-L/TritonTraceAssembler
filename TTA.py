# idapython fix <= 7.6
# DO NOT REMOVE ME
import sys
sys.stdout.encoding = 'utf-8'


import idaapi



class TTA(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = "TTA"
    wanted_hotkey = ""

    def __init__(self):
        super(TestPlugin, self).__init__()

    def init(self):
        from tracer.ui import UIManager
        self.ui = UIManager()

        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def term(self):
        self.ui.ui_action_handler_unregister()
        pass



def PLUGIN_ENTRY():
    return TTA()
