
from idaapi import *
from idc import *
from idautils import *

class tracer_read_dialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:address}
BUTTON YES* Read
BUTTON CANCEL Cancel
Read Memory
{reg_label}
<##:{address}>
""", {
        'reg_label': Form.StringLabel("Enter the address in hex format"),
        'address': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })



class tracer_read_size_dialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:size}
BUTTON YES* Read
BUTTON CANCEL Cancel
Read Memory
{reg_label}
<##:{size}>
""", {
        'reg_label': Form.StringLabel("Enter the size (1,2,4,8,16,32,64) "),
        'size': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })



class tracer_write_data_dialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:addr_value}
BUTTON YES* Write
BUTTON CANCEL Cancel
Write Memory
{reg_label}
<##:{addr_value}>
""", {
        'reg_label': Form.StringLabel("Enter a value ex. [0xDEADBEEF] "),
        'addr_value': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })


class tracer_change_register(Form):
    def __init__(self,regName):
        Form.__init__(self, r"""STARTITEM {id:reg_val}
BUTTON YES* Write
BUTTON CANCEL Cancel
Write Memory
{reg_label}
<##:{reg_val}>
""", {
        'reg_label': Form.StringLabel("Enter a value for " + regName + "" ),
        'reg_val': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })


class tracer_context_menu_dialog(Choose):

    def __init__(self, triton, regs, flags=0, width=None, height=None, embedded=False):
        Choose.__init__(
            self,
            "CPU Context Menu",
            [ ["Register", 10], ["Value", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = regs
        self.tracer = triton
        self.icon = -1
        self.selcount = 0
        self.popup_names = [ "", "", "Edit Register Value", "" ]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = str( hex ( self.tracer.change_register_dialog(self.items[n][0]) ) )
        self.Refresh()

    def OnSelectLine(self, n):
        return self.OnEditLine(n)


    def OnGetLine(self, n):
        # [Register, Value] both str
        return [ self.items[n][0].getName(), self.items[n][1] ]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(True) >= 0


class tracer_taint_mem_dialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:address}
BUTTON YES* Read
BUTTON CANCEL Cancel
Read Memory
{reg_label}
<##:{address}>
""", {
        'reg_label': Form.StringLabel("Enter the address in hex format"),
        'address': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })



class tracer_taint_mem_size_dialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:size}
BUTTON YES* Read
BUTTON CANCEL Cancel
Read Memory
{reg_label}
<##:{size}>
""", {
        'reg_label': Form.StringLabel("Enter the size (1,2,4,8,16,32,64) "),
        'size': Form.NumericInput(tp=Form.FT_HEX, swidth=20)
        })

class tracer_taint_menu_dialog(Choose):

    def __init__(self, triton, regs, flags=0, width=None, height=None, embedded=False):
        Choose.__init__(
            self,
            "Taint Context Menu",
            [ ["Register", 10], ["Value", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = regs
        self.tracer = triton
        self.icon = -1
        self.selcount = 0
        self.popup_names = [ "", "", "Taint/Untaint Register", "" ]

    def OnClose(self):
        pass

    def OnEditLine(self, n):
        self.items[n][1] = str( ( self.tracer.taint_register(self.items[n][0]) )  )
        self.Refresh()

    def OnSelectLine(self, n):
        return self.OnEditLine(n)


    def OnGetLine(self, n):
        # [Register, Value] both str
        return [ self.items[n][0].getName(), self.items[n][1] ]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(True) >= 0