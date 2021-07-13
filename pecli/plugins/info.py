#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
import magic
import copy
from pecli.plugins.base import Plugin
from pecli.lib.dotnet_guid import get_guid, is_dot_net_assembly
from pecli.lib.utils import debug_filename, debug_guid
from pecli.lib.richpe import get_richpe_hash, get_richpe_info
from pecli.lib.utils import cli_out, search_section


class PluginInfo(Plugin):

    name = "info"
    description = "Extract info from the PE file"

    def hashes_info(self, pe, data, cli_mode=False):
        """Display md5, sha1, sh256, and imphash of the data given"""
        
        res = {}

        # compute md5, sha1, sha256
        for algo in ["md5", "sha1", "sha256"]:
            m = getattr(hashlib, algo)()
            m.update(data)
            h = m.hexdigest()
            cli_out("%-15s %s" % (algo.upper()+":", h), cli_mode)
            res[algo.lower()] = h

        # get imphash
        imphash = pe.get_imphash()
        cli_out("%-15s %s" % ("Imphash:", pe.get_imphash()), cli_mode)
        if imphash:
            res["imphash"] = imphash
        return res

    def headers_info(seld, pe, cli_mode=False):
        """Display header information"""

        res = {}

        # check if file is a DLL
        if pe.FILE_HEADER.IMAGE_FILE_DLL:
            cli_out("DLL File!", cli_mode)
            res["is_dll"] = True

        # gather compile time
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time = str(datetime.datetime.utcfromtimestamp(timestamp))
        cli_out("Compile Time:\t%s (UTC - 0x%-8X)"  %(compile_time, timestamp), cli_mode)
        res["compile_time"] = compile_time

        return res

    def imports_info(self, pe, cli_mode=False):
        """Display imports"""

        res = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:

                # get the dll name
                dll = entry.dll.decode('utf-8')
                cli_out(dll, cli_mode)

                for i in entry.imports:

                    # get the address, ordinal, and function name
                    addr = str(hex(i.address))
                    ordinal = str(i.ordinal) if i.ordinal else None
                    name = i.name.decode('utf-8') if i.name else None
 
                    if dll not in res:
                        res[dll] = []

                    import_res = {
                        "address": addr
                    }
                    if name:
                        import_res["name"] = name
                    if ordinal:
                        import_res["ordinal"] = ordinal

                    res[dll].append(import_res)

                    # display
                    # TODO allow for both ordinal and name being present in cli mode
                    if name:
                        cli_out('\t%s %s' % (addr, name), cli_mode)
                    else:
                        cli_out('\t%s ordinal: %s' % (addr, ordinal), cli_mode)

        # flatten the non-key-descriptive res into one that is
        new_res = []
        for dll in res:
            new_res.append({
                "library": dll,
                "imports": res[dll]
            })

        return {"library_imports": new_res} if new_res else {}

    def exports_info(self, pe, cli_mode=False):
        """exports"""

        exports = []
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                name = exp.name.decode('utf-8', 'ignore')
                ordinal = exp.ordinal
                cli_out("%s %s %s" % (address, name, ordinal), cli_mode)
                exports.append({
                    "address": address,
                    "name": name,
                    "ordinal": ordinal
                })
        except AttributeError:
            pass
        
        return {"exports": exports} if exports else {}

    # TODO causes crashes
    def debug_info(self, pe):
        """Display debug infos"""
        debug_fn = debug_filename(pe)
        try:
            debug_g = debug_guid(pe)
        except TypeError:
            print("Error in computing Debug GUID")
            debug_g = None
        if debug_fn:
            print("Debug Filename:\t{}".format(debug_fn))
        if debug_g:
            print("Debug GUID:\t{}".format(debug_g))

    def resources_info(self, pe, cli_mode=False):
        """resources"""

        def resource_info(pe, r, parents):
            """Recursive info of resources"""

            # resource
            if hasattr(r, "data"):

                # gather all the info
                offset = r.data.struct.OffsetToData
                size = r.data.struct.Size
                data = pe.get_memory_mapped_image()[offset:offset+size]
                parents_path = "/".join(parents) + "/"
                path =  parents_path + str(r.id) if not r.name else parents_path + r.name
                m = hashlib.md5()
                m.update(data)
                md5 = m.hexdigest()
                magic_type = magic.from_buffer(data)
                lang = pefile.LANG.get(r.data.lang, 'UNKNOWN')
                sublang = pefile.get_sublang_name_for_lang(r.data.lang, r.data.sublang)

                # display it if we want
                cli_out("%-19s %-9s %-14s %-17s %-14s %-9s" % (
                        path,
                        "%i B" % size,
                        lang,
                        sublang,
                        magic_type,
                        md5
                    ),
                    cli_mode
                )

                # return it in a dict
                return [{"path": path, "size": size, "md5": md5, "magic_type": magic_type, 
                    "lang": lang, "sublang": sublang}]

            # directory
            else:

                res = []

                # append this name or ID to the parents list
                parents = copy.copy(parents)
                if r.id is not None:
                    parents.append(str(r.id))
                else:
                    parents.append(r.name.string.decode('utf-8'))

                for r2 in r.directory.entries:
                    res += resource_info(pe, r2, parents)

                return res

        res = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            if(len(pe.DIRECTORY_ENTRY_RESOURCE.entries) > 0):
                cli_out("Resources:", cli_mode)
                cli_out("=" * 80, cli_mode)
                cli_out("%-19s %-9s %-14s %-17s %-14s %-9s" % ("Path(IDs or Names)", "Size", "Lang", "Sublang", "Type", "MD5"), cli_mode)
                for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res += resource_info(pe, r, [])

        return {"resources": res} if res else {}

    def magic_type_info(self, data, cli_mode=False):
        magic_type = magic.from_buffer(data)
        cli_out("Type:\t\t%s" % magic_type, cli_mode)
        return {"magic_type": magic_type}

    def size_info(self, data, cli_mode=False):
        size = len(data)
        cli_out("Size:\t\t%d bytes" % size, cli_mode)
        return {"size": str(size)}

    def entry_point_info(self, pe, cli_mode=False):
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        section = search_section(pe, entry_point, physical=False)
        entry_point = hex(entry_point)
        cli_out("Entry point:\t%s (section %s)" % (entry_point, section), cli_mode)
        return {"entry_point": {"address": entry_point, "section_name": section}}

    def dotnet_guid_info(self, pe, data, cli_mode=False):
        res = {}
        if is_dot_net_assembly(pe):
            try:
                r = get_guid(pe, data)
                if "mvid" in r:
                    cli_out(".NET MVid\t{}".format(r["mvid"]), cli_mode)
                    res["module_version_id"] = r["mvid"]
                if "typelib_id" in r:
                    cli_out(".NET TypeLib\t{}".format(r['typelib_id']), cli_mode)
                    res["typelib_id"] = r["typelib_id"]
            except:
                cli_out("Impossible to parse .NET GUID", cli_mode)
        return res

    def richpe_info(self, pe, cli_mode=False):

        res = {}

        if pe.RICH_HEADER:
            info = get_richpe_info(pe)
            cli_out("ProdId\tVersion\tCount\tProduct", cli_mode)
            for i in info:
                res = {
                    "product_id": i["prodid"],
                    "version": i["version"],
                    "count": i["count"]
                }
                if i['product']:
                    res["product"] = i["product"]
                    cli_out("{}\t{}\t{}\t{}".format(
                            i['prodid'],
                            i['version'],
                            i['count'],
                            i['product']
                        ),
                        cli_mode
                    )
                else:
                    cli_out("{}\t{}\t{}".format(
                            i['prodid'],
                            i['version'],
                            i['count']
                        ),
                        cli_mode
                    )
            rich_hash = get_richpe_hash(pe)
            cli_out("\nRichPE Hash: {}".format(rich_hash), cli_mode)
            res["md5"] = rich_hash

        else:
            cli_out("No RichPE Header", cli_mode)

        return {"richpe": res} if res else {}

    def sections_info(self, pe, cli_mode=False):
        """information about the PE sections"""

        sections = []
        cli_out("{:9} {:4} {:10} {:10} {:9} {:9} {:8} {}".format("Name", "RWX", "VirtSize", 
            "VirtAddr", "RawAddr", "RawSize", "Entropy", "md5"), cli_mode)
        for section in pe.sections:
            name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            m = hashlib.md5()
            m.update(section.get_data())
            md5 = m.hexdigest()

            permissions = ""
            if section.IMAGE_SCN_MEM_READ:
                permissions += "R"
            else:
                permissions += "-"

            if section.IMAGE_SCN_MEM_WRITE:
                permissions += "W"
            else:
                permissions += "-"

            if section.IMAGE_SCN_MEM_EXECUTE:
                permissions += "X"
            else:
                permissions += "-"

            vsize = hex(section.Misc_VirtualSize)
            vaddr = hex(section.VirtualAddress)
            raw_addr = hex(section.PointerToRawData)
            size = hex(section.SizeOfRawData)
            entropy = section.get_entropy()

            cli_out("{:9} {:4} {:10} {:10} {:9} {:9} {:6.2f} {}".format(name, permissions, vsize, 
                vaddr, raw_addr, size, entropy, md5), cli_mode)
            sections.append({"name": name, "permissions": permissions, "virtual_size": vsize, 
                "virtual_address": vaddr, "raw_address": raw_addr, "raw_size": size, 
                "entropy": entropy, "md5": md5})

        cli_out("", cli_mode)
        return {"sections": sections} if sections else {}

    def get_results(self, pe, data):
        res = {}
        res.update(self.hashes_info(pe, data))
        res.update(self.headers_info(pe))
        res.update(self.imports_info(pe))
        res.update(self.exports_info(pe))
        res.update(self.resources_info(pe))
        res.update(self.magic_type_info(data))
        res.update(self.size_info(data))
        res.update(self.entry_point_info(pe))
        res.update(self.dotnet_guid_info(pe, data))
        res.update(self.richpe_info(pe))
        res.update(self.sections_info(pe))
        return res

    def add_arguments(self, parser):
        parser.add_argument('--sections', '-s', action='store_true', help='Only display sections')
        parser.add_argument('--imports', '-i',  action='store_true', help='Display imports only')
        parser.add_argument('--exports', '-e',  action='store_true', help='Display exports only')
        parser.add_argument('--resources', '-r',  action='store_true', help='Display resources only')
        parser.add_argument('--full', '-f',  action='store_true', help='Full dump of all pefile infos')
        parser.add_argument('--richpe', '-rp', action='store_true', help="Display RichPE only")
        self.parser = parser

    def run_cli(self, args, pe, data):
        if args.sections:
            display_sections(pe)
            sys.exit(0)
        if args.imports:
            self.imports_info(pe, cli_mode=True)
            sys.exit(0)
        if args.exports:
            self.exports_info(pe, cli_mode=True)
            sys.exit(0)
        if args.resources:
            self.resources_info(pe, cli_mode=True)
            sys.exit(0)
        if args.richpe:
            self.richpe_info(pe, cli_mode=True)
            sys.exit(0)
        if args.full:
            print(pe.dump_info())
            sys.exit(0)

        # Metadata
        print("Metadata")
        print("=" * 80)
        self.hashes_info(pe, data, cli_mode=True)
        self.magic_type_info(data, cli_mode=True)
        self.size_info(data, cli_mode=True)
        self.headers_info(pe, cli_mode=True)
        self.entry_point_info(pe, cli_mode=True)
        self.dotnet_guid_info(pe, data, cli_mode=True)
        self.richpe_info(pe, cli_mode=True)

        # causes crashes
        #self.debug_info(pe)

        # Sections
        print("")
        print("Sections")
        print("=" * 80)
        self.sections_info(pe, cli_mode=True)
        print("")
        print("Imports")
        print("=" * 80)
        self.imports_info(pe, cli_mode=True)
        print("")
        self.exports_info(pe, cli_mode=True)
        print("")
        self.resources_info(pe, cli_mode=True)
