from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT
import sys
import os
import re

class Binja(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'executable/.*'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 2
    SERVICE_RAM_MB = 768
    SERVICE_DEFAULT_CONFIG = {
        'license': None,
        'binaryninja_location': '/opt/al/support/binaryninja/python',
        'signature_file': '/opt/al/pkg/al_services/alsvc_binja/sigs.json'
    }

    class ACall():
        def __init__(self, il, typ, name, args=[]):
            self.il = il
            self.b = None
            self.typ = typ
            self.name = name
            self.args = args

    def __init__(self, cfg=None):
        super(Binja, self).__init__(cfg)
        self.syms = []
        self.sym_const = {}
        self.apiscore = 0
        self.depth = 0
        self.bv = None
        self.calls = {}
        self.used_syms = {}
        self.functions = {}
        self.processed = {}
        self.pstrs = []
        self.sigs = []
        self.proc_arg = {"KERNEL32!LOADLIBRARY": [0],
                         "KERNEL32!GETPROCADDRESS": [1],
                         "KERNEL32!GETMODULEHANDLE": [0],
                         "KERNEL32!OPENEVENT": [2],
                         "SHELL32!SHELLEXECUTE": [1]
                         }

    def start(self):
        self.log.debug("Binja service started")
        self.load_sigs(self.cfg.get('signature_file'))

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global binaryninja
        sys.path.extend([self.cfg.get('binaryninja_location')])
        import binaryninja

    def get_unicode_str_at(self, addr):
        br = binaryninja.BinaryReader(self.bv)
        br.seek(addr)
        c = br.read16()
        s = ''
        while (c != 0) and (c < 0x80) and c is not None:
            s += chr(c)
            c = br.read16()
        return s

    def get_ascii_str_at(self, addr):
        br = binaryninja.BinaryReader(self.bv)
        br.seek(addr)
        c = br.read8()
        s = ''
        while (c != 0) and (c < 0x80) and c is not None:
            s += chr(c)
            c = br.read8()
        return s

###########################################################################

    def check_condition(self, cond, il, matches, depth=0, blocks=[]):
        flen = len(il.function)
        f = il.function.source_function
        b = f.get_basic_block_at(il.address)
        while il.operation != binaryninja.LowLevelILOperation.LLIL_RET:
            depth += 1
            if depth > cond['max']:
                return
            if il.operation == binaryninja.LowLevelILOperation.LLIL_JUMP_TO or il.operation == binaryninja.LowLevelILOperation.LLIL_IF:
                for edge in b.outgoing_edges:
                    if edge.target in blocks:
                        if "RECUR" in cond['tgts']:
                            matches.append({"il": f.get_low_level_il_at(edge.target.start), "blocks": blocks})
                        self.check_condition(cond, f.get_low_level_il_at(edge.target.start), matches, depth)
                    else:
                        newb = list(blocks)
                        newb.append(edge.target)
                        self.check_condition(cond, f.get_low_level_il_at(edge.target.start), matches, depth, newb)
                return
            elif il.operation == binaryninja.LowLevelILOperation.LLIL_GOTO:
                il = il.function[il.dest]
                depth -= 1  # Don't count this LLIL_INSTR
            elif il.operation == binaryninja.LowLevelILOperation.LLIL_CALL:
                AC = self.process_call(il)
                if AC.name in cond['tgts'] or AC.name[:-1] in cond['tgts'] or AC.typ in cond['tgts']:
                    matches.append({"il": il, "blocks": blocks})
                il = il.function[il.instr_index + 1]
            else:
                if (il.instr_index + 1) == flen:
                    return
                il = il.function[il.instr_index + 1]

    def check_api_sig(self, sig, results):
        starts = []
        matches = []
        for i in sig['init']:
            for c in self.calls:
                if i in self.calls[c].name:
                    starts.append(self.calls[c])
        for start in starts:
            matches.append({"il": start.il, "blocks": []})
        for cond in sig['conditions']:
            if len(matches) == 0:
                return False
            preMatches = list(matches)
            matches = []
            for match in preMatches:
                self.check_condition(cond, match["il"], matches, 0, match["blocks"])
        for match in matches:
            results[match["il"].function.source_function.start] = match["il"].function.source_function

        return results

    def load_sigs(self, fn):
        import json
        with open(fn) as sig_file:
            self.sigs = json.load(sig_file)
        self.load_syms()

    def load_syms(self):
        for sig in self.sigs:
            for init in sig['init']:
                if init not in self.syms:
                    self.syms.append(init)
            for cond in sig['conditions']:
                for tgt in cond['tgts']:
                    if "!" in tgt and tgt not in self.syms:
                        self.syms.append(tgt)

###########################################################################

    def process_call(self, il):
        name = ''
        typ = 'UNK'
        if il.address in self.calls:
            return self.calls[il.address]
        if il.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_REG:
            #rval = il.function.source_function.get_reg_value_at_low_level_il_instruction(il.instr_index, str(il.dest))
            rval = il.get_reg_value(str(il.dest))
            if rval.type is binaryninja.RegisterValueType.ConstantValue:
                if rval.value in self.sym_const:
                    typ = "API"
                    name = self.sym_const[rval.value].name.split("@IAT")[0]
                else:
                    name = "%x" % rval.value
            else:
                typ = "REG"
                name = str(il.dest)
        elif il.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_LOAD:
            if il.operands[0].src.operation == binaryninja.LowLevelILOperation.LLIL_CONST:
                try:
                    typ = "API"
                    name = self.bv.get_symbol_at(il.operands[0].src.constant).name.split("@IAT")[0]
                except AttributeError:
                    name = "%s" % il
        elif il.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST:
            try:
                typ = "API"
                name = self.bv.get_symbol_at(il.operands[0].constant).name
            except AttributeError:
                try:
                    typ = "LOC"
                    name = self.bv.get_function_at(il.operands[0].constant).name
                    if il.operands[0].constant == il.function.source_function.start:
                        typ = "SELF"
                        name = name
                except AttributeError:
                    name = "%s" % il
        else:
            name = "%d" % il.operands[0].operation
        if name[0:3] == 'sub':
            typ = "LOC"
        AC = self.ACall(il, typ, name.upper())
        self.calls[il.address] = AC
        return AC

    def dump_function_linear(self, func, depth=0, dump_str=[]):
        pre = "*" * depth
        dump_str.append(pre + func.name)
        for s in func.stack_layout:
            dump_str.append("%s\t%s" % (pre, str(s)))
        for block in func.low_level_il:
            dump_str.append("%s\t\t%s" % (pre, block))
            for il in block:
                dump_str.append("%s\t\t%d: %s" % (pre, il.instr_index, il))
                if il.operation == binaryninja.LowLevelILOperation.LLIL_CALL:
                    AC = self.process_call(il)
                    func.set_comment(il.address, "%s(%s)" % (AC.name, ','.join([str(x) for x in AC.args])))
                    if AC.typ == 'LOC':
                        if depth < self.depth:
                            dump_str.append("%s\t\t\t\t[%s] %s(%s)" % (
                                pre, AC.typ, AC.name, ','.join([str(x) for x in AC.args])))
                            nf = self.bv.get_function_at(il.operands[0].constant)
                            self.dump_function_linear(nf, depth + 1, dump_str)
                        else:
                            if "-D" not in AC.name:
                                AC.name = AC.name + "-D"
                                dump_str.append("%s\t\t\t\t[%s] %s(%s)" % (
                                    pre, AC.typ, AC.name, ','.join([str(x) for x in AC.args])))
                    else:
                        dump_str.append(
                            "%s\t\t\t\t[%s] %s(%s)" % (pre, AC.typ, AC.name, ','.join([str(x) for x in AC.args])))
                        # dump_str.append("%s\t\t\t\t[%s] %s(%s)" % (pre, AC.typ, AC.name, ','.join([str(x) for x in AC.args])))
        if "-A" not in func.name:
            func.name = func.name + "-A"

    def process_target_functions(self):
        for strt in self.functions:
            dstr = []
            if strt not in self.processed:
                self.dump_function_linear(self.functions[strt], dump_str=dstr)
                self.processed[strt] = dstr
        return

###########################################################################

    def get_symbol_xrefs(self, sym_str):
        try:
            sym = self.bv.symbols[sym_str]
        except KeyError:
            return
        xrefs = self.bv.get_code_refs(sym.address)
        for xref in xrefs:
            if xref.function.start not in self.functions:
                self.functions[xref.function.start] = xref.function
        if len(xrefs):
            self.apiscore += 1
            if sym.name.split("@IAT")[0].upper() not in self.used_syms:
                self.used_syms[sym.name.split("@IAT")[0].upper()] = len(xrefs)
            else:
                self.used_syms[sym.name.split("@IAT")[0].upper()] += len(xrefs)


    def symbol_usage(self, tgt_syms=[]):
        br = binaryninja.BinaryReader(self.bv)
        for sym in self.bv.get_symbols():
            br.seek(sym.address)
            c = br.read32()
            self.sym_const[c] = sym
        for s in self.bv.symbols:
            ts = s.split("@IAT")[0].upper()
            if ts in self.syms:
                self.get_symbol_xrefs(s)
            if ts[:-1] in self.syms:
                self.get_symbol_xrefs(s)

###########################################################################

    def get_str_arg(self, f, il, argv_index, api):
        p = f.get_parameter_at_low_level_il_instruction(il.instr_index, f.function_type, argv_index)
        v = -1
        if p.type == binaryninja.function.RegisterValueType.ConstantValue:
            v = p.constant
        elif p.type == binaryninja.function.RegisterValueType.UndeterminedValue:
            block_start = f.get_basic_block_at(il.address).start
            pil = f.low_level_il[il.instr_index - 1]
            pcount = 0
            while pil.address >= block_start:
                if pil.operation == binaryninja.LowLevelILOperation.LLIL_PUSH:
                    if pcount == argv_index:
                        if pil.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST:
                            v = pil.operands[0].constant
                            break
                    pcount += 1
                pil = f.low_level_il[pil.instr_index - 1]
        if v == -1:
            val = "Undetermined"
        elif v == 0:
            val = "Self"
        elif api[-1] == "A":
            val = self.get_ascii_str_at(v)
        elif api[-1] == "W":
            val = self.get_unicode_str_at(v)
        else:
            val = self.get_ascii_str_at(v)
        if self.calls.has_key(il.address):
            self.calls[il.address].args.append(val)
        else:
            AC = self.ACall(il, "API", api.upper(), [val])
            self.calls[il.address] = AC

    def find_str_arg(self, sym, arg):
        # Try to identify string used as an arg
        xrefs = self.bv.get_code_refs(sym.address)
        for xref in xrefs:
            try:
                il = xref.function.low_level_il[xref.function.get_low_level_il_at(xref.address)]
                if il.operation == binaryninja.LowLevelILOperation.LLIL_CALL:
                    self.get_str_arg(xref.function, il, arg, sym.name.split("@IAT")[0])
                    # elif il.operation == binaryninja.LowLevelILOperation.LLIL_SET_REG:
                    # Track REG and find CALLS
                    # Iterate over calls, calling preproc_get_arg
            except IndexError:
                pass
        return

    def preprocess(self):
        for s in self.bv.symbols:
            s_ = s.upper()
            for api in self.proc_arg.keys():
                if api in s_:
                    for arg in sorted(self.proc_arg[api]):
                        self.find_str_arg(self.bv.symbols[s], arg)

    def linear_sweep(self):
        prologues = ["\x55\x8b\xec", "\x8b\xff\x56", "\x8b\xff\x55", "\xff\x25"]
        for prologue in prologues:
            cur = self.bv.find_next_data(self.bv.start, prologue)
            nf = self.bv.get_next_function_start_after(self.bv.start)
            while cur:
                if cur < nf:
                    self.bv.add_function(cur)
                    cur = self.bv.find_next_data(cur + 1, prologue)
                elif cur == nf:
                    nf = self.bv.get_next_function_start_after(cur)
                    cur = self.bv.find_next_data(cur + 1, prologue)
                else:
                    nf = self.bv.get_next_function_start_after(cur)

###########################################################################

    def clean_structures(self):
        self.sym_const = {}
        self.apiscore = 0
        self.calls = {}
        self.used_syms = {}
        self.functions = {}
        self.processed = {}
        self.pstrs = []
        self.bv = None

    def execute(self, request):
        file_path = request.download()
        filename = os.path.basename(file_path)
        bndb = os.path.join(self.working_directory, "%s.bndb" % filename)
        disas = os.path.join(self.working_directory, filename)

        self.clean_structures()

        if request.tag.startswith("executable/windows/"):
            self.bv = binaryninja.BinaryViewType['PE'].open(file_path)
        else:
            return

        if self.bv is None:
            return

        result = Result()
        self.bv.update_analysis_and_wait()
        # Preparation
        self.linear_sweep()
        self.preprocess()
        self.symbol_usage()
        self.process_target_functions()
        # Check Signatures
        for sig in self.sigs:
            results = {}
            self.check_api_sig(sig, results)
            if len(results) > 0:
                for res in results:
                    rn = "%s - %s" % (results[res].name.split("-A")[0], sig['name'])
                    section = ResultSection(sig['score'], rn)
                    if res in self.processed:
                        fn = "%s_%s" % (disas, rn.replace(" ", "_"))
                        with open(fn, "wb") as fp:
                            fp.write("\n".join("%s" % l for l in self.processed[res]))
                            request.add_supplementary(fn, "Linear Disassembly of Matched Function", rn + ".disas")
                    results[res].name = rn
                    result.add_section(section)
        # Finalize Results and Store BNDB
        self.bv.create_database(bndb)
        request.add_supplementary(bndb, "Binary Ninja DB", filename + ".bndb")
        section = ResultSection(self.apiscore, "Target Symbols X-refs")
        for sym in sorted(self.used_syms.items(), key=lambda x:x[1], reverse=True):
            section.add_line("%d\t%s" % (sym[1], sym[0]))
        result.add_section(section)
        request.result = result

        self.clean_structures()
