#! /usr/bin/env python
import pefile
import datetime
import yara
import os
import copy
from pecli.plugins.base import Plugin
from pecli.lib.utils import cli_out


class PluginCrypto(Plugin):
    name = "crypto"
    description = "Identifies cryptographic values"

    def add_arguments(self, parser):
        self.parser = parser

    def convert_physical_addr(self, pe, addr):
        """
        Convert a physical address into its logical address
        """
        for s in pe.sections:
            if (addr >= s.PointerToRawData) and (addr <= s.PointerToRawData + s.SizeOfRawData):
                vaddr = pe.OPTIONAL_HEADER.ImageBase + addr - s.PointerToRawData + s.VirtualAddress
                return (s.Name.decode('utf-8', 'ignore').strip('\x00'), vaddr)
        return (None, None)


    def get_results(self, pe, data, cli_mode=False):

        crypto_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/yara-crypto.yar"
        if not os.path.isfile(crypto_db):
            if cli_mode:
                print("Problem accessing the yara database")
            else:
                raise Exception("Problem accessing the yara database")

        rules = yara.compile(filepath=crypto_db)
        matches = rules.match(data=data)
        results = []
        if len(matches) > 0:
            for match in matches:

                paddr = match.strings[0][0]
                results.append({
                    "rule": match.rule,
                    "address": hex(paddr)
                })

                # try to pin down the virtual/logical address if we can
                # TODO add to non-cli mode?
                section, vaddr = self.convert_physical_addr(pe, paddr)
                if section:
                    cli_out("Found : {} at {} ({} - {})".format(
                        match.rule,
                        hex(paddr),
                        section,
                        hex(vaddr)
                    ), cli_mode)
                else:
                    cli_out("Found : {} at {} (Virtual Address and section not found)".format(match.rule, hex(paddr)), cli_mode)
        else:
            cli_out("No cryptographic data found!", cli_mode)

        return {} if not results else {"crypto_matches": results}

    def run_cli(self, args, pe, data):
        self.get_results(pe, data, cli_mode=True)
