
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