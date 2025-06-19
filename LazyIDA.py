from __future__ import division
from __future__ import print_function
from struct import unpack
import idaapi
import idautils
import idc
import ida_ida

from unicorn import *
from unicorn.x86_const import *

from PyQt5.Qt import QApplication

ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(10)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYEA = "lazyida:copyea"
ACTION_COPYFO = "lazyida:copyfo"
ACTION_GOTOCLIPEA = "lazyida:gotoclipea"
ACTION_GOTOCLIPFO = "lazyida:gotoclipfo"
ACTION_XORDATA = "lazyida:xordata"
ACTION_FILLNOP = "Qfrost:fillnop"
ACTION_GOTOEA = "huskygg:gotoea"
ACTION_EMULATE = "Qfrost:emulate"
ACTION_REINIT_EMULATOR = "Qfrost:reinit_emulator"
ACTION_XREF = "lazycross:xref"

ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"
ACTION_HX_COPYEA = "lazyida:hx_copyea"
ACTION_HX_COPYFO = "lazyida:hx_copyfo"
ACTION_HX_COPYNAME = "lazyida:hx_copyname"
ACTION_HX_GOTOCLIPEA = "lazyida:hx_gotoclipea"
ACTION_HX_GOTOCLIPFO = "lazyida:hx_gotoclipfo"

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

ARCH = 0
BITS = 0

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def clip_text():
    return QApplication.clipboard().text()

def jump_ea():
    ea_point = idc.here()
    ea = idc.read_dbg_dword(ea_point)
    if idc.jumpto(ea):
        print("jump to 0x%x success" % ea)
    else:
        print("0x%x jump err" % ea)

def parse_location(loc, is_fo=False):
    is_named = False
    ascii_text = ""
    try:
        loc = int(loc, 16)
        if is_fo:
            loc = idaapi.get_fileregion_ea(loc)
    except ValueError:
        try:
            ascii_text = loc.encode(encoding="ascii",errors="replace").decode(encoding="ascii").strip()
            loc = idc.get_name_ea_simple(ascii_text)
            is_named = True
        except:
            return idaapi.BADADDR
    return loc, is_named, ascii_text


def read_memory(addr, size) -> bytes:
    mem = b""
    for addr in range(addr, addr + size):
        mem += idaapi.get_wide_byte(addr).to_bytes( 1, "little")
    return mem

class Emulator(Uc):

    STACK = 0x7F00000000
    PAGE_SIZE = 0x1000

    emu_lastinstr_addr = 0
    mmap = list()

    def __init__(self) -> None:
        Uc.__init__(self, UC_ARCH_X86, UC_MODE_64)

        self.mmap.clear()
        self.emu_lastinstr_addr = 0

        # initialize stack
        self.mem_map(self.STACK, 2*0x1000)
        self.reg_write(UC_X86_REG_RBP, self.STACK + 0x1000)
        self.reg_write(UC_X86_REG_RSP, self.STACK)
        self.reg_write(UC_X86_REG_DR7, 0x400)

        # hook
        self.hook_add(UC_HOOK_CODE, self.hooked_code)
        self.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hooked_invalid_memory_read)

        print("[+] Emulator initialize successful")
        pass


    def page_align(self, addr) -> int:
        return (addr // self.PAGE_SIZE) * self.PAGE_SIZE
    

    
    def ptr_valid(self, addr) -> bool:
        for map_base, size in self.mmap:
            if addr >= map_base and addr < map_base + size:
                return True
        return False

    def map_seg(self, addr):
        seg = idaapi.getseg(addr)
        map_base = self.page_align(seg.start_ea)
        map_size = self.page_align(seg.end_ea - map_base)
        if map_size == 0:
            map_size = self.PAGE_SIZE

        print("[+] Enter map:", hex(map_base), hex(map_size))
        self.mem_map(map_base, map_size )
        code = read_memory(seg.start_ea, seg.end_ea - seg.start_ea)
        self.mem_write(seg.start_ea, code)
        self.mmap.append( (map_base, map_size) )
        print("[+] Mapped seg: ", idaapi.get_segm_name(seg), hex(seg.start_ea), hex(seg.end_ea))

        pass

    def hooked_code(self, emu, address, size, user_data):
        print(" - ", hex(address))
        instr = idaapi.print_insn_mnem(emulator.emu_lastinstr_addr)
        if instr == "pxor" or instr == "xor":
            dec_reg = None
            dec_buf_reg = None
            buf_size = 0
            if "xmm0" in idaapi.print_operand(emulator.emu_lastinstr_addr, 0):
                dec_reg = "XMM0"
                dec_buf_reg = UC_X86_REG_XMM0
                buf_size = 16
            elif "rax" in idaapi.print_operand(emulator.emu_lastinstr_addr, 0):
                dec_reg = "RAX"
                dec_buf_reg = UC_X86_REG_RAX
                buf_size = 8
            else:
                print("[-] Unsupport decrypt instr:", hex(emulator.emu_lastinstr_addr))
                emulator.emu_lastinstr_addr = address
                return

            print(f"[+] {dec_reg}: {hex(emu.reg_read(dec_buf_reg))}")
            decrypted_str = emulator.reg_read(dec_buf_reg).to_bytes(buf_size, "little").decode()
            print("[+] Decrypt string:", decrypted_str)
            idaapi.set_cmt(address, decrypted_str, True)

            cfunc = idaapi.decompile(address)
            tl = idaapi.treeloc_t()
            tl.ea = address
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, decrypted_str)
            cfunc.save_user_cmts()
            
            emu.emu_stop()
        emulator.emu_lastinstr_addr = address


    def hooked_invalid_memory_read(self, emu, access, address, size, value, user_data):

        if access == UC_MEM_READ_UNMAPPED:
            print("Invalid memory read at address:", hex(address))
            emulator.map_seg(address)
            print("[+] Continue running...")
                
            return True         # Unicorn continue running
        else:
            print("[-] Unexpected memory read at address : ", access)
        
        return False    # unhandle
    
    def emulate(self, start_address, end_address):
        # Map .text
        if emulator.ptr_valid(start_address) == False:
            emulator.map_seg(start_address)
        self.emu_lastinstr_addr = start_address
        print("[+] Emulating {:X} -> {:X}".format(start_address, end_address))
        emulator.emu_start(start_address, end_address)

emulator = Emulator()

class VulnChoose(idaapi.Choose):
    """
    Chooser class to display result of format string vuln scan
    """
    def __init__(self, title, items, icon, embedded=False):
        idaapi.Choose.__init__(self, title, [["Address", 20], ["Function", 30], ["Format", 30]], embedded=embedded)
        self.items = items
        self.icon = 45

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idc.jumpto(int(self.items[n][0], 16))

class hotkey_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hotkey actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_COPYEA:
            ea = idc.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("Address 0x%X (EA) has been copied to clipboard" % ea)
        elif self.action == ACTION_COPYFO:
            ea = idc.get_screen_ea()
            if ea != idaapi.BADADDR:
                fo = idaapi.get_fileregion_offset(ea)
                if fo != idaapi.BADADDR:
                    copy_to_clip("0x%X" % fo)
                    print("Address 0x%X (FO) has been copied to clipboard" % fo)
        elif self.action == ACTION_GOTOCLIPEA:
            loc, is_named, name = parse_location(clip_text(), False)
            if loc != idaapi.BADADDR:
                if is_named:
                    print("Goto named location '%s' 0x%X" % (name, loc))
                else:
                    print("Goto location 0x%X (EA)" % loc)
                idc.jumpto(loc)
        elif self.action == ACTION_GOTOCLIPFO:
            loc, is_named, name = parse_location(clip_text(), True)
            if loc != idaapi.BADADDR:
                if is_named:
                    print("Goto named location '%s' 0x%X" % (name, loc))
                else:
                    print("Goto location 0x%X (FO)" % idaapi.get_fileregion_offset(loc))
                idc.jumpto(loc)
        elif self.action == ACTION_GOTOEA:
            jump_ea()
        elif self.action == ACTION_REINIT_EMULATOR:
            global emulator
            emulator = Emulator()
        return 1

    def update(self, ctx):
        if idaapi.IDA_SDK_VERSION >= 770:
            target_attr = "widget_type"
        else:
            target_attr = "form_type"

        if idaapi.IDA_SDK_VERSION >= 900:
            try:
                dump_type = idaapi.BWN_HEXVIEW
            except:
                dump_type = idaapi.BWN_DUMP
        else:
            dump_type = idaapi.BWN_DUMP

        if ctx.__getattribute__(target_attr) in (idaapi.BWN_DISASM, dump_type):
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE] else idaapi.AST_DISABLE_FOR_WIDGET


    def activate(self, ctx):
        if self.action in ACTION_CONVERT:
            # convert (dump as)
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
                size = end - start + 1
            elif idc.get_item_size(idc.get_screen_ea()) > 1:
                start = idc.get_screen_ea()
                size = idc.get_item_size(start)
                end = start + size
            else:
                return False

            data = idc.get_bytes(start, size)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            name = idc.get_name(start, idc.GN_VISIBLE)
            if not name:
                name = "data"
            if data:
                print("\n[+] Dump 0x%X - 0x%X (%u bytes) :" % (start, end, size))
                if self.action == ACTION_CONVERT[0]:
                    # escaped string
                    output = '"%s"' % "".join("\\x%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[1]:
                    # hex string
                    output = "".join("%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[2]:
                    # C array
                    output = "unsigned char %s[%d] = {" % (name, size)
                    for i in range(size):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%02X, " % data[i]
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[3]:
                    # C array word
                    data += b"\x00"
                    array_size = (size + 1) // 2
                    output = "unsigned short %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 2):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[4]:
                    # C array dword
                    data += b"\x00" * 3
                    array_size = (size + 3) // 4
                    output = "unsigned int %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 4):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[5]:
                    # C array qword
                    data += b"\x00" * 7
                    array_size = (size + 7) // 8
                    output = "unsigned long %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 8):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%016X, " % u64(data[i:i+8])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[6]:
                    # python list
                    output = "[%s]" % ", ".join("0x%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[7]:
                    # python list word
                    data += b"\x00"
                    output = "[%s]" % ", ".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2))
                elif self.action == ACTION_CONVERT[8]:
                    # python list dword
                    data += b"\x00" * 3
                    output = "[%s]" % ", ".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))
                elif self.action == ACTION_CONVERT[9]:
                    # python list qword
                    data += b"\x00" * 7
                    output = "[%s]" %  ", ".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8)).replace("0X", "0x")
                copy_to_clip(output)
                print(output)
        elif self.action == ACTION_XORDATA:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
            else:
                if idc.get_item_size(idc.get_screen_ea()) > 1:
                    start = idc.get_screen_ea()
                    end = start + idc.get_item_size(start)
                else:
                    return False

            data = idc.get_bytes(start, end - start)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            x = idaapi.ask_long(0, "Xor with...")
            if x:
                x &= 0xFF
                print("\n[+] Xor 0x%X - 0x%X (%u bytes) with 0x%02X:" % (start, end, end - start, x))
                print(repr("".join(chr(b ^ x) for b in data)))
        elif self.action == ACTION_FILLNOP:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
                end += idaapi.decode_insn(idaapi.insn_t(), end)
                idaapi.patch_bytes(start, b"\x90" * (end - start))
                print("\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % (start, end, end - start))
            else:
                length = 0
                patch_addr = idaapi.get_screen_ea()
                if idaapi.print_insn_mnem(patch_addr) == None:
                    length = 1      # is not an instr
                else:
                    length = idaapi.decode_insn(idaapi.insn_t(), patch_addr)
                idaapi.patch_bytes(patch_addr, b"\x90" * length)
                print("\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % (patch_addr, patch_addr + length, length))
        elif self.action == ACTION_SCANVUL:
            print("\n[+] Finding Format String Vulnerability...")
            found = []
            for addr in idautils.Functions():
                name = idc.get_func_name(addr)
                if "printf" in name and "v" not in name and idc.get_segm_name(addr) in (".text", ".plt", ".idata", ".plt.got"):
                    xrefs = idautils.CodeRefsTo(addr, False)
                    for xref in xrefs:
                        vul = self.check_fmt_function(name, xref)
                        if vul:
                            found.append(vul)
            if found:
                print("[!] Done! %d possible vulnerabilities found." % len(found))
                ch = VulnChoose("Vulnerability", found, None, False)
                ch.Show()
            else:
                print("[-] No format string vulnerabilities found.")
        elif self.action == ACTION_EMULATE:
            global emulator
            print("Click ACTION_EMULATE : ", hex(idaapi.get_screen_ea()))

            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start_addr, end_addr = t0.place(view).toea(), t1.place(view).toea()
                end_addr += idaapi.decode_insn(idaapi.insn_t(), end_addr)
            else:
                start_addr = idaapi.get_screen_ea()
                end_addr = start_addr + 0x1000
            emulator.emulate(start_addr, end_addr)
        elif self.action == ACTION_XREF:
            if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(ctx.widget)
                ea = vu.item.get_ea()
            elif ctx.widget_type == idaapi.BWN_DISASM:
                ea = idaapi.get_screen_ea()
            else:
                return 0

            try:
                idaapi.show_wait_box("Processing...")
                show_xref(ea)
            except KeyboardInterrupt:
                print("LazyCross: User interrupted")
            finally:
                idaapi.hide_wait_box()
        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    @staticmethod
    def check_fmt_function(name, addr):
        """
        Check if the format string argument is not valid
        """
        function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)

        while True:
            addr = idc.prev_head(addr)
            op = idc.print_insn_mnem(addr).lower()
            dst = idc.print_operand(addr, 0)

            if op in ("ret", "retn", "jmp", "b") or addr < function_head:
                return

            c = idc.get_cmt(addr, 0)
            if c and c.lower() == "format":
                break
            elif name.endswith(("snprintf_chk",)):
                if op in ("mov", "lea") and dst.endswith(("r8", "r8d", "[esp+10h]")):
                    break
            elif name.endswith(("sprintf_chk",)):
                if op in ("mov", "lea") and (dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                             dst.endswith("ecx") and BITS == 64):
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and (dst.endswith(("rdx", "[esp+8]", "R2")) or
                                             dst.endswith("edx") and BITS == 64):
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and (dst.endswith(("rsi", "[esp+4]", "R1")) or
                                             dst.endswith("esi") and BITS == 64):
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and (dst.endswith(("rdi", "[esp]", "R0")) or
                                             dst.endswith("edi") and BITS == 64):
                    break

        # format arg found, check its type and value
        # get last oprend
        op_index = idc.generate_disasm_line(addr, 0).count(",")
        op_type = idc.get_operand_type(addr, op_index)
        opnd = idc.print_operand(addr, op_index)

        if op_type == idc.o_reg:
            # format is in register, try to track back and get the source
            _addr = addr
            while True:
                _addr = idc.prev_head(_addr)
                _op = idc.print_insn_mnem(_addr).lower()
                if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                    break
                elif _op in ("mov", "lea", "ldr") and idc.print_operand(_addr, 0) == opnd:
                    op_type = idc.get_operand_type(_addr, 1)
                    opnd = idc.print_operand(_addr, 1)
                    addr = _addr
                    break

        if op_type == idc.o_imm or op_type == idc.o_mem:
            # format is a memory address, check if it's in writable segment
            op_addr = idc.get_operand_value(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return

        print("0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd))
        return ["0x%X" % addr, name, opnd]

class hexrays_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hexrays actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
        self.ret_type = {}

    def activate(self, ctx):
        if self.action == ACTION_HX_REMOVERETTYPE:
            vdui = idaapi.get_widget_vdui(ctx.widget)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        elif self.action == ACTION_HX_COPYEA:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("Address 0x%X (EA) has been copied to clipboard" % ea)
        elif self.action == ACTION_HX_COPYFO:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                fo = idaapi.get_fileregion_offset(ea)
                if fo != idaapi.BADADDR:
                    copy_to_clip("0x%X" % fo)
                    print("Address 0x%X (FO) has been copied to clipboard" % fo)
        elif self.action == ACTION_HX_COPYNAME:
            highlight = idaapi.get_highlight(idaapi.get_current_viewer())
            name = highlight[0] if highlight else None
            if name:
                copy_to_clip(name)
                print("'%s' has been copied to clipboard" % name)
        elif self.action == ACTION_HX_GOTOCLIPEA:
            loc, is_named, name = parse_location(clip_text(), False)
            if loc != idaapi.BADADDR:
                if is_named:
                    print("Goto named location '%s' 0x%X" % (name, loc))
                else:
                    print("Goto location 0x%X (EA)" % loc)
                idc.jumpto(loc)
        elif self.action == ACTION_HX_GOTOCLIPFO:
            loc, is_named, name = parse_location(clip_text(), True)
            if loc != idaapi.BADADDR:
                if is_named:
                    print("Goto named location '%s' 0x%X" % (name, loc))
                else:
                    print("Goto location 0x%X (FO)" % idaapi.get_fileregion_offset(loc))
                idc.jumpto(loc)
        else:
            return 0

        return 1

    def update(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET

    def remove_rettype(self, vu):
        if vu.item.citype == idaapi.VDI_FUNC:
            # current function
            ea = vu.cfunc.entry_ea
            old_func_type = idaapi.tinfo_t()
            if not vu.cfunc.get_func_type(old_func_type):
                return False
        elif vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr():
            # call xxx
            ea = vu.item.get_ea()
            old_func_type = idaapi.tinfo_t()

            func = idaapi.get_func(ea)
            if func:
                try:
                    cfunc = idaapi.decompile(func)
                except idaapi.DecompilationFailure:
                    return False

                if not cfunc.get_func_type(old_func_type):
                    return False
            else:
                return False
        else:
            return False

        fi = idaapi.func_type_data_t()
        if ea != idaapi.BADADDR and old_func_type.get_func_details(fi):
            # Return type is already void
            if fi.rettype.is_decl_void():
                # Restore ret type
                if ea not in self.ret_type:
                    return True
                ret = self.ret_type[ea]
            else:
                # Save ret type and change it to void
                self.ret_type[ea] = fi.rettype
                ret = idaapi.BT_VOID

            # Create new function info with new rettype
            fi.rettype = idaapi.tinfo_t(ret)

            # Create new function type with function info
            new_func_type = idaapi.tinfo_t()
            new_func_type.create_func(fi)

            # Apply new function type
            if idaapi.apply_tinfo(ea, new_func_type, idaapi.TINFO_DEFINITE):
                return vu.refresh_view(True)

        return False

class XrefChoose(idaapi.Choose):
    def __init__(self, title, items):
        idaapi.Choose.__init__(self, title, [["Address", 30], ["Pseudocode line", 80]], embedded=False, width=100, icon=40)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        item = self.items[n]
        return [idc.get_func_off_str(item["addr"]), item["line"]]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idaapi.jumpto(self.items[n]["addr"])


class ObjVisitor(idaapi.ctree_visitor_t):
    def __init__(self, ea, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.found = []
        self.target_ea = ea
        self.cfunc = cfunc

    def visit_expr(self, expr):
        # check callee ea
        if expr.obj_ea != self.target_ea:
            return 0

        # find top expr
        e = expr
        addr = expr.ea
        while True:
            p = self.cfunc.body.find_parent_of(e)
            if not p or p.op > idaapi.cit_empty:
                break
            e = p
            if e.ea != idaapi.BADADDR:
                addr = e.ea

        self.found.append({
            "addr": addr,
            "line": idaapi.tag_remove(e.print1(None))
        })
        return 0

def show_xref(ea):
    name = idaapi.get_name(ea)
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    if demangled:
        name = demangled
    print(f"LazyCross: Find cross reference to {name}...")

    found = []
    checked = []
    for ref in idautils.XrefsTo(ea, False):
        if idaapi.user_cancelled():
            raise KeyboardInterrupt

        frm = ref.frm
        if not idaapi.is_code(idaapi.get_flags(frm)):
            continue

        func = idaapi.get_func(frm)
        func_name = idaapi.get_func_name(frm)
        if not func:
            print(f"LazyCross: Reference is not from a function: 0x{frm:x}")
            continue

        if func.start_ea in checked:
            continue
        checked.append(func.start_ea)

        try:
            cfunc = idaapi.decompile(func)
        except idaapi.DecompilationFailure as e:
            print(f"LazyCross: Decompile {func_name} failed")
            print(str(e))
            continue

        if not cfunc:
            print(f"LazyCross: cfunc is none: {func_name}")
            continue

        cv = ObjVisitor(ea, cfunc)
        try:
            cv.apply_to(cfunc.body, None)
        except Exception as e:
            print(cfunc)
            print(e)
        found += cv.found

    if found:
        ch = XrefChoose(f"Cross references to {name}", found)
        ch.Show()
    else:
        print("LazyCross: No xrefs found")

class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if idaapi.IDA_SDK_VERSION >= 900:
            try:
                dump_type = idaapi.BWN_HEXVIEW
            except:
                dump_type = idaapi.BWN_DUMP
        else:
            dump_type = idaapi.BWN_DUMP

        idaapi.attach_action_to_popup(form, popup, ACTION_FILLNOP, None)

        if form_type == idaapi.BWN_DISASM or form_type == dump_type:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1) or idc.get_item_size(idc.get_screen_ea()) > 1:
                idaapi.attach_action_to_popup(form, popup, ACTION_XORDATA, None)
                for action in ACTION_CONVERT:
                    idaapi.attach_action_to_popup(form, popup, action, "Dump/")

            # Add xref action
            ea = idaapi.get_screen_ea()
            if ea == idaapi.BADADDR:
                idaapi.attach_action_to_popup(form, popup, ACTION_XREF, None)

        if form_type == idaapi.BWN_DISASM and (ARCH, BITS) in [(idaapi.PLFM_386, 32),
                                                               (idaapi.PLFM_386, 64),
                                                               (idaapi.PLFM_ARM, 32),]:
            idaapi.attach_action_to_popup(form, popup, ACTION_SCANVUL, None)
            idaapi.attach_action_to_popup(form, popup, ACTION_EMULATE, None)
        

class HexRays_Hook(object):
    def callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, phandle, vu = args
            if vu.item.citype == idaapi.VDI_FUNC or (vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr()):
                idaapi.attach_action_to_popup(form, phandle, ACTION_HX_REMOVERETTYPE, None)
            # Add xref action for pseudocode
            if vu.item.get_ea() != idaapi.BADADDR:
                idaapi.attach_action_to_popup(form, phandle, ACTION_XREF, None)
        elif event == idaapi.hxe_double_click:
            vu, shift_state = args
            # auto jump to target if clicked item is xxx->func();
            if vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr():
                expr = idaapi.tag_remove(vu.item.e.print1(None))
                if "->" in expr:
                    # find target function
                    name = expr.split("->")[-1]
                    addr = idc.get_name_ea_simple(name)
                    if addr == idaapi.BADADDR:
                        # try class::function
                        e = vu.item.e
                        while e.x:
                            e = e.x
                        addr = idc.get_name_ea_simple("%s::%s" % (str(e.type).split()[0], name))

                    if addr != idaapi.BADADDR:
                        idc.jumpto(addr)
                        return 1
        return 0

class LazyIDA_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "NepIDA"
    help = ""
    wanted_name = "NepIDA"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        global ARCH
        global BITS
        ARCH = idaapi.ph_get_id()

        if idaapi.IDA_SDK_VERSION >= 900:
            if idaapi.inf_is_64bit():
                BITS = 64
            elif idaapi.inf_is_32bit_exactly():
                BITS = 32
            elif idaapi.inf_is_16bit():
                BITS = 16
            else:
                raise ValueError
        else:
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                BITS = 64
            elif info.is_32bit():
                BITS = 32
            else:
                BITS = 16

        print("NepIDA (v1.0.0.5) plugin has been loaded.")

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_CONVERT[0], "Dump as string", menu_action_handler_t(ACTION_CONVERT[0]), None, None, 80),
            idaapi.action_desc_t(ACTION_CONVERT[1], "Dump as hex string", menu_action_handler_t(ACTION_CONVERT[1]), None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[2], "Dump as C/C++ array (BYTE)", menu_action_handler_t(ACTION_CONVERT[2]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[3], "Dump as C/C++ array (WORD)", menu_action_handler_t(ACTION_CONVERT[3]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[4], "Dump as C/C++ array (DWORD)", menu_action_handler_t(ACTION_CONVERT[4]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[5], "Dump as C/C++ array (QWORD)", menu_action_handler_t(ACTION_CONVERT[5]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[6], "Dump as python list (BYTE)", menu_action_handler_t(ACTION_CONVERT[6]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[7], "Dump as python list (WORD)", menu_action_handler_t(ACTION_CONVERT[7]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[8], "Dump as python list (DWORD)", menu_action_handler_t(ACTION_CONVERT[8]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[9], "Dump as python list (QWORD)", menu_action_handler_t(ACTION_CONVERT[9]), None, None, 201),
            idaapi.action_desc_t(ACTION_XORDATA, "Get xored data", menu_action_handler_t(ACTION_XORDATA), None, None, 9),
            idaapi.action_desc_t(ACTION_FILLNOP, "Fill with NOPs", menu_action_handler_t(ACTION_FILLNOP), None, None, 9),
            idaapi.action_desc_t(ACTION_SCANVUL, "Scan format string vulnerabilities", menu_action_handler_t(ACTION_SCANVUL), None, None, 160),
            idaapi.action_desc_t(ACTION_EMULATE, "Emulate", menu_action_handler_t(ACTION_EMULATE), None, None, 9),
            idaapi.action_desc_t(ACTION_XREF, "LazyCross", menu_action_handler_t(ACTION_XREF), "Ctrl+X", None, 40),
        )
        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Register hotkey actions
        hotkey_actions = (
            idaapi.action_desc_t(ACTION_COPYEA, "Copy EA", hotkey_action_handler_t(ACTION_COPYEA), "w", "Copy current EA", 0),
            idaapi.action_desc_t(ACTION_COPYFO, "Copy FO", hotkey_action_handler_t(ACTION_COPYFO), "Shift-W", "Copy current FO", 0),
            idaapi.action_desc_t(ACTION_GOTOCLIPEA, "Goto clipboard EA", hotkey_action_handler_t(ACTION_GOTOCLIPEA), "Shift-G"),
            idaapi.action_desc_t(ACTION_GOTOCLIPFO, "Goto clipboard FO", hotkey_action_handler_t(ACTION_GOTOCLIPFO), "Ctrl-Shift-G"),
        )
        for action in hotkey_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        # Add hexrays ui callback
        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "nepnep.team"
            addon.name = "LazyIDA"
            addon.producer = "Nepnep"
            addon.url = "https://github.com/NepnepSec/NepIDA"
            addon.version = "1.0.0.5"
            idaapi.register_addon(addon)

            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_REMOVERETTYPE, "Remove return type", hexrays_action_handler_t(ACTION_HX_REMOVERETTYPE), "v"),
                idaapi.action_desc_t(ACTION_HX_COPYEA, "Copy EA", hexrays_action_handler_t(ACTION_HX_COPYEA), "w", "Copy current EA", 0),
                idaapi.action_desc_t(ACTION_HX_COPYFO, "Copy FO", hexrays_action_handler_t(ACTION_HX_COPYFO), "Shift-W", "Copy current FO", 0),
                idaapi.action_desc_t(ACTION_HX_GOTOCLIPEA, "Goto clipboard EA", hexrays_action_handler_t(ACTION_HX_GOTOCLIPEA), "Shift-G"),
                idaapi.action_desc_t(ACTION_HX_GOTOCLIPFO, "Goto clipboard FO", hexrays_action_handler_t(ACTION_HX_GOTOCLIPFO), "Ctrl-Shift-G"),
                idaapi.action_desc_t(ACTION_HX_COPYNAME, "Copy name", hexrays_action_handler_t(ACTION_HX_COPYNAME), "c"),
            )
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            self.hx_hook = HexRays_Hook()
            idaapi.install_hexrays_callback(self.hx_hook.callback)
            self.hexrays_inited = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if hasattr(self, "ui_hook"):
            self.ui_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)
            if self.hx_hook:
                idaapi.remove_hexrays_callback(self.hx_hook.callback)
            idaapi.term_hexrays_plugin()

def PLUGIN_ENTRY():
    return LazyIDA_t()
