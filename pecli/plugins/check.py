#! /usr/bin/env python
import pefile
import datetime
import yara
import os
import copy
from pecli.plugins.base import Plugin
from pecli.lib.utils import cli_out, search_section

class CheckResults():
    # just take whatever the check functions 
    def __init__(self, results_dict):
        self.__dict__ = results_dict

class PluginCheck(Plugin):
    name = "check"
    description = "Do various checks for suspicious indicators"
    # Known suspicious sections partially imported from
    # https://github.com/katjahahn/PortEx/blob/master/src/main/java/com/github/katjahahn/tools/anomalies/SectionTableScanning.scala
    # http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    know_suspicious_sections = {
	    ".arch":  "Alpha-architecture section",
	    ".bindat": "Binary data, e.g., by downware installers",
	    ".cormeta": "CLR Metadata section",
	    ".complua": "LUA compiler",
        ".fasm": "Flat Assembler",
        ".flat" : "Flat Assembler",
	    ".idlsym": "IDL Attributes (registered SEH)",
	    ".impdata": "Alternative import section",
	    ".orpc": "Code section inside rpcrt4.dll",
	    ".rodata": "Read-only data section",
	    ".script": "Section containing script",
	    ".stab" : "GHC (Haskell)",
        ".stabstr" : "GHC (Haskell)",
	    ".sxdata" : "Registered Exception Handlers section",
	    ".xdata" : "Exception information section",
	    "DGROUP" : "Legacy data group section",
	    "BSS" : "Uninitialized Data section (Borland)",
	    "CODE" : "Code section (Borland)",
	    "DATA" : "Data section (Borland)",
	    "INIT" : "INIT section of drivers",
        "PAGE" : "PAGE section of drivers",
	    ".aspack" : "Aspack packer",
        ".adata" : "Aspack/Armadillo packer",
	    "ASPack" : "Aspack packer",
        ".ASPack" : "Aspack packer",
	    ".asspck" : "Aspack packer",
        ".boom": "The Boomerang List Builder",
	    ".ccg" : "CCG Packer (Chinese)",
	    "BitArts" : "Crunch 2.0 Packer",
	    "DAStub" : "DAStub Dragon Armor protector",
	    ".charmve" : "Added by the PIN tool",
        ".ecode": "Developed with  Easy Programming Language (EPL)",
        ".edata": "Developed with  Easy Programming Language (EPL)",
	    ".enigma1" : "Enigma Virtual Box protector",
	    ".enigma2" : "Enigma Virtual Box protector",
	    "!EPack" : "EPack packer",
        ".gentee": "Gentee installer",
        ".kkrunchy": "kkrunchy Packer",
        "lz32.dll": "Crinkler",
	    ".mackt" : "ImpRec-created section, this file was patched/cracked",
	    ".MaskPE" : "MaskPE Packer",
	    "MEW" : "MEW packer",
	    ".MPRESS1" : "MPRESS Packer",
	    ".MPRESS2" : "MPRESS Packer",
        ".neolite" : "Neolite Packer",
        ".neolit" : "Neolite Packer",
        ".ndata" : "Nullsoft Installer",
        ".nsp0" : "NsPack packer",
        ".nsp1" : "NsPack packer",
        ".nsp2" : "NsPack packer",
        "nsp0" : "NsPack packer",
        "nsp0" : "NsPack packer",
        "nsp0" : "NsPack packer",
        ".packed" : "RLPack Packer", #  first section only
        "pebundle" : "PEBundle Packer",
        "PEBundle" : "PEBundle Packer",
        "PEC2TO" : "PECompact packer",
        "PEC2" : "PECompact packer",
        "pec1" : "PECompact packer",
        "pec2" : "PECompact packer",
        "PEC2MO" : "PECompact packer",
        "PEC2TO" : "PECompact packer",
        "PECompact2" : "PECompact packer",
        "PELOCKnt" : "PELock Protector",
        ".perplex" : "Perplex PE-Protector",
        "PESHiELD" : "PEShield Packer",
        ".petite" : "Petite Packer",
        ".pinclie" : "Added by the PIN tool",
        "ProCrypt" : "ProCrypt Packer",
        ".RLPack" : "RLPack Packer", # second section
        ".rmnet" : "Ramnit virus marker",
        "RCryptor" : "RPCrypt Packer",
        ".RPCrypt" : "RPCrypt Packer",
        ".seau": "SeauSFX Packer",
        ".sforce3" : "StarForce Protection",
        ".spack" : "Simple Pack (by bagie)",
        ".svkp" : "SVKP packer",
        ".Themida" : "Themida",
        "Themida" : "Themida",
        ".tsuarch" : "TSULoader",
        ".tsustub" : "TSULoader",
        "PEPACK!!" : "Pepack",
        ".Upack" : "Upack packer",
        ".ByDwing" : "Upack packer",
        "UPX0" : "UPX packer", 
        "UPX1" : "UPX packer", 
        "UPX2" : "UPX packer",
        "UPX!" : "UPX packer", 
        ".UPX0" : "UPX packer", 
        ".UPX1" : "UPX packer",
        ".UPX2" : "UPX packer",
        ".vmp0" : "VMProtect packer",
        ".vmp1" : "VMProtect packer",
        ".vmp2" : "VMProtect packer",
        "VProtect" : "Vprotect Packer",
        "WinLicen" : "WinLicense (Themida) Protector",
        ".WWPACK" : "WWPACK Packer",
        ".yP" : "Y0da Protector",
        ".y0da" : "Y0da Protector"
    }
    normal_sections = [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    imphashes = {
        "25c0914e1e7dc7c3bb957d88e787a155": "Enigma VirtualBox"
    }
    resource_names = {
        "PYTHONSCRIPT": "PY2EXE binary",
        "PYTHON27.DLL": "PY2EXE binary"
    }

    def _normal_section_name(self, section_name):

        if isinstance(section_name, bytes):
            n = section_name.decode('utf-8', 'ignore').strip('\x00')
        else:
            n = section_name.strip('\x00')
        return n in self.normal_sections

    def check_abnormal_section_name(self, pe, cli_mode=False):

        res = [x.Name.decode('utf-8', 'ignore').strip('\x00') for x in pe.sections if not self._normal_section_name(x.Name)]
        if len(res) > 0:
            cli_out("[+] Abnormal section names: %s" % " ".join(res), cli_mode)
            return {"abnormal_section_names": res}
        else:
            return {}

    def check_known_suspicious_sections(self, pe, cli_mode=False):

        names = [x.Name.decode('utf-8', 'ignore').strip('\x00') for x in pe.sections]

        res = []
        for name in names:
            sus_section = self.know_suspicious_sections.get(name)
            if sus_section:
                res.append({
                    "section_name": name,
                    "description": sus_section 
                })

        if len(res) > 0:
            cli_out("[+] Known suspicious sections", cli_mode)
            for r in res:
                cli_out("\t-%s: %s" % (r["section_name"], r["description"]), cli_mode)

            return {"suspicious_sections": res}
        else:
            return {}

    def check_section_entropy(self, pe, cli_mode=False):
        
        res = []
        for s in pe.sections:
            if s.get_entropy() < 1  or s.get_entropy() > 7:
                res.append({
                    "section_name": s.Name.decode('utf-8', 'ignore').strip('\x00'),
                    "entropy": s.get_entropy()
                })

        if len(res) > 0:
            if len(res) == 1:
                cli_out("[+] Suspicious section's entropy: %s - %3f" % ( res[0]["section_name"], res[0]["entropy"]), cli_mode)
            else:
                cli_out("[+] Suspicious entropy in the following sections:", cli_mode)
                for r in res:
                    cli_out("\t- %s - %3f" % (r["section_name"], r["entropy"]), cli_mode)

            return {"suspicious_entropy_sections": res}
        else:
            return {}

    def check_imphash(self, pe, cli_mode=False):
        """Check imphash in a list of known import hashes"""

        ih = pe.get_imphash()
        if ih in self.imphashes:
            cli_out("[+] Known suspicious import hash: %s" % (self.imphashes[ih]), cli_mode)
            return {"sus_imp_hash": self.imphashes[ih]}
        return {}

    def check_pe_size(self, pe, data, cli_mode=False):
        """Check for extra data in the PE file by comparing PE info and data size"""

        length = max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))
        if length < len(data):
            cli_out("[+] %i extra bytes in the file" % (len(data) - length), cli_mode)
            return {"extra_bytes": len(data) - length}
        else:
            return {}

    def check_pe_sections(self, pe, cli_mode=False):
        """Search for PE headers at the beginning of sections"""

        res = []
        for section in pe.sections:
            if b"!This program cannot be run in DOS mode" in section.get_data()[:400] or \
                    b"This program must be run under Win32" in section.get_data()[:400]:
                res.append(section.Name.decode('utf-8').strip('\x00'))

        if len(res) > 0:
            cli_out("[+] PE header in sections %s" % " ".join(res), cli_mode)
            return {"pe_header_in_sections": res}
        return {}

    def check_tls(self, pe, cli_mode=False):
        """Check if there are TLS callbacks"""

        res = {}
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0:
                    break
                callbacks.append({
                    "address": "0x%x" % func,
                    "section": search_section(pe, func, physical=False)
                })
                idx += 1

        if callbacks:

            res["tls_callbacks"] = callbacks

            # display the results
            if len(callbacks) == 1:
                cli_out("TLS Callback:\t%s (section %s)" % (callbacks[0]["address"], callbacks[0]["section"]), cli_mode)
            else:
                cli_out("TLS Callbacks:", cli_mode)
                for c in callbacks:
                    cli_out("\t\t%s (section %s)" % (c["address"], c["section"]), cli_mode)

        return res

    def check_peid(self, data, cli_mode=False):
        """Check on PEid signatures"""

        peid_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/PeID.yar"
        rules = yara.compile(filepath=peid_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            cli_out("[+] PeID packer: %s" % ", ".join([a.rule for a in matches]), cli_mode)
            return {"peid_packer": [a.rule for a in matches]}
        return {}

    def check_timestamp(self, pe, cli_mode=False):
        """check for suspicious timestamps"""

        date = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        if (date.year < 2005) or (date > datetime.datetime.now()):
            cli_out("[+] Suspicious timestamp : %s" % str(date), cli_mode)
            return {"suspicious_timestamp": str(date)}
        return {}

    def check_pe_resources(self, pe, cli_mode=False):
        """
        Check if there are any suspicious resource entries
        """

        def merge_sus_resources(cur_res, new_res):
            """merge results from this method to another result of this method."""

            for key in new_res:
                if key not in cur_res:
                    cur_res[key] = new_res[key]
                else:
                    cur_res[key] = cur_res[key] + new_res[key]

        def check_resource(pe, resource, parents, cli_mode=False):
            """
            Recursive cecking/printing of suspicious resources. A resource is suspicious if it 
            itself contains a PE header or the resource is a directory and it's name is a known 
            name we're tracking as suspicious.
            """

            if hasattr(resource, "data"):
                # Resource
                offset = resource.data.struct.OffsetToData
                size = resource.data.struct.Size
                data = pe.get_memory_mapped_image()[offset:offset+size]
                if data.startswith(b'\x4d\x5a\x90\x00\x03\x00'):
                    if resource.name:
                        name = '/'.join(parents) + '/' + str(resource.name)
                    else:
                        name = '/'.join(parents) + '/' + str(resource.id)
                    cli_out('[+] PE header in resource {}'.format(name), cli_mode)
                    return {"embedded_pe_resources": [name]}
                else:
                    return {}
            else:
                # directory
                result = {}
                parents = copy.copy(parents)
                suspicious = False

                if resource.id is not None:
                    parents.append(str(resource.id))
                # resources with no IDs are sus
                else:
                    # TODO test this part. haven't found a sample yet with one of these
                    name = resource.name.string.decode('utf-8')
                    parents.append(name)
                    if name in self.resource_names:
                        cli_out("[+] resource with no ID: {} -> {}".format(
                            name,
                            self.resource_names[name]),
                            cli_mode
                        )
                        sus_resource = {
                            "resource": name,
                            "description": self.resource_names[name]
                        }
                        if "no_id_resources" not in result:
                            result["no_id_resources"] = [sus_resource]
                        else:
                            result["no_id_resources"].append(sus_resource)

                # recurse and merge the downstream results into this one
                for child_resource in resource.directory.entries:
                    merge_sus_resources(result, check_resource(pe, child_resource, parents, cli_mode))

                return result

        result = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                merge_sus_resources(result, check_resource(pe, resource, [], cli_mode))

        return result

    def get_results(self, pe, data, cli_mode=False):
        """
        Call all the check functions to produce a CheckResults object
        """
        
        results = {}
        results.update(self.check_pe_resources(pe, cli_mode))
        results.update(self.check_timestamp(pe, cli_mode))
        results.update(self.check_peid(data, cli_mode))
        results.update(self.check_tls(pe, cli_mode))
        results.update(self.check_pe_sections(pe, cli_mode))
        results.update(self.check_pe_size(pe, data, cli_mode))
        results.update(self.check_section_entropy(pe, cli_mode))
        results.update(self.check_known_suspicious_sections(pe, cli_mode))
        results.update(self.check_abnormal_section_name(pe, cli_mode))
     
        return {"suspicious": results} if results else results

    def run_cli(self, args, pe, data):

        print("Running checks on %s:" % args.PEFILE)

        results = self.get_results(pe, data, cli_mode=True)
        if not results:
            print("Nothing suspicious found")
            return
