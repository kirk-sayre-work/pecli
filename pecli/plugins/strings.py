#! /usr/bin/env python
import pefile
import datetime
import os
import re
from pecli.plugins.base import Plugin
from pecli.lib.utils import cli_out


ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"


class PluginStrings(Plugin):

    name = "strings"
    description = "Extract strings from the PE file"


    def add_arguments(self, parser):
        parser.add_argument('--ascii', '-a', action="store_true", help="ASCII strings only")
        parser.add_argument('--wide', '-w', action="store_true", help="Wide strings only")
        parser.add_argument('-n', '--min-len', type=int, default=4, help='Print sequences of ' +
                            'characters that are at least min-len characters long, instead of ' +
                            'the default 4.')
        self.parser = parser


    def get_results(self, data, min_len=4, wide_only=False, ascii_only=False, cli_mode=False):

        # regular expressions from flare-floss:
        #  https://github.com/fireeye/flare-floss/blob/master/floss/strings.py#L7-L9
        re_narrow = re.compile(b'([%s]{%d,})' % (ASCII_BYTE, min_len))
        re_wide = re.compile(b'((?:[%s]\x00){%d,})' % (ASCII_BYTE, min_len))

        strings = []

        # print ascii strings unless we only want wide strings
        if not wide_only:
            for match in re_narrow.finditer(data):
                s = match.group().decode('ascii')
                strings.append(s)
                cli_out(s, cli_mode)

        # print wide strings unless we only want ascii strings
        if not ascii_only:
            for match in re_wide.finditer(data):
                try:
                    s = match.group().decode('utf-16')
                    cli_out(s, cli_mode)
                    strings.append(s)
                except UnicodeDecodeError:
                    pass

        return {"strings": strings}


    def run_cli(self, args, pe, data):

        if args.ascii and args.wide:
            print("to print both ascii and wide strings, omit both")

        else:
            self.get_results(data, args.min_len, args.wide, args.ascii, cli_mode=True)
