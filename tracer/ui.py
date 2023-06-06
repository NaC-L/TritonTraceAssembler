from __future__ import print_function
import ida_kernwin
import idaapi

from tracer.TTA_tracer import *


Tracer = TritonTracer()


class tracer_run_here_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        
        Tracer.run()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class tracer_set_until_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        Tracer.set_sym_ex_end()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class tracer_clear_selection(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        Tracer.clear_selection(idaapi.get_screen_ea())
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class tracer_paste_assembled(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        Tracer.set_paste()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class tracer_registers_list_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        Tracer.context_menu_dialog()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class tracer_read_memory_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        
        Tracer.read_Memory_Access()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class tracer_write_memory_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        
        Tracer.write_Memory_Access()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class tracer_load_binary_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        Tracer.loadBinary()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class do_nothing(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

_act_dests = [
    
    ida_kernwin.action_desc_t(
        "TTA:Run from here", "Run from here", tracer_run_here_action()),
    ida_kernwin.action_desc_t(
        "TTA:Run until here", "Set tracer endpoint", tracer_set_until_action()),
    ida_kernwin.action_desc_t(
        "TTA:Paste Assembled Trace Here", "Paste assembled trace here", tracer_paste_assembled()),
    ida_kernwin.action_desc_t(
        "TTA:Clear selection", "Clear selection", tracer_clear_selection()),
    ida_kernwin.action_desc_t(
        "TTA:-", "-", do_nothing()),
    ida_kernwin.action_desc_t(
        "TTA:Context menu", "Context menu", tracer_registers_list_action()),
    ida_kernwin.action_desc_t(
        "TTA:-", "-", do_nothing()),
    ida_kernwin.action_desc_t(
        "TTA:Read memory", "Read memory", tracer_read_memory_action()),
    ida_kernwin.action_desc_t(
        "TTA:Write memory", "Write memory", tracer_write_memory_action()),
    ida_kernwin.action_desc_t(
        "TTA:-", "-", do_nothing()),
    ida_kernwin.action_desc_t(
        "TTA:Load Current Binary", "Load current binary", tracer_load_binary_action())
]


class HooksUI(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            for act_dest in _act_dests:
                ida_kernwin.attach_action_to_popup(
                    widget, popup, act_dest.name, "TTA/")


class UIManager():
    def __init__(self) -> None:
        self.ui_action_handler_register()
        self.hooks_ui = HooksUI()
        self.hooks_ui.hook()

    def __del__(self):
        self.hooks_ui = None
        self.ui_action_handler_unregister()

    def ui_action_handler_unregister(self):
        Tracer.term()
        for act_dest in _act_dests:
            ida_kernwin.detach_action_from_menu(
                f"Edit/TTA1/{act_dest.name}", act_dest.name)
            # ida_kernwin.unregister_action(act_dest.name)

    def ui_action_handler_register(self):
        for act_dest in _act_dests:
            if not ida_kernwin.register_action(act_dest):
                print(f'warning failed register_action({act_dest.name})')
            ida_kernwin.attach_action_to_menu(
                f"Edit/TTA1/{act_dest.name}", act_dest.name, ida_kernwin.SETMENU_APP)
