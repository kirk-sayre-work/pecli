#! /usr/bin/env python

import pefile
import datetime
import yara
import os
import copy
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from asn1crypto import cms

from pecli.plugins.base import Plugin
from pecli.lib.utils import cli_out

# TODO find out how to get this programatically
OID_NAME_MAP = {
    NameOID.COMMON_NAME: "Common Name",
    NameOID.COUNTRY_NAME: "Country Name",
    NameOID.LOCALITY_NAME: "Locality Name",
    NameOID.STATE_OR_PROVINCE_NAME: "State or Province Name",
    NameOID.STREET_ADDRESS: "Street Name",
    NameOID.ORGANIZATION_NAME: "Organization Name",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "Organizational Unit Name",
    NameOID.SURNAME: "Surname",
    NameOID.GIVEN_NAME: "Given Name",
    NameOID.TITLE: "Title",
    NameOID.GENERATION_QUALIFIER: "Generation Qualifier",
    NameOID.X500_UNIQUE_IDENTIFIER: "X500 Unique Identifier",
    NameOID.DN_QUALIFIER: "Distinguished Name Qualifier",
    NameOID.PSEUDONYM: "Pseudonum",
    NameOID.USER_ID: "User ID",
    NameOID.DOMAIN_COMPONENT: "Domain Component",
    NameOID.EMAIL_ADDRESS: "Email Address",
    NameOID.JURISDICTION_COUNTRY_NAME: "Jurisdiction Country Name",
    NameOID.JURISDICTION_LOCALITY_NAME: "Jurisdiction Locality Name",
    NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: "Jurisdiction State or Province Name",
    NameOID.BUSINESS_CATEGORY: "Business Category",
    NameOID.POSTAL_ADDRESS: "Postal Address",
    NameOID.POSTAL_CODE: "Postal Code",
    NameOID.SERIAL_NUMBER: "Serial Number"
    #NameOID.UNSTRUCTURED_NAME: "Unstructured Name"
}

class PluginSig(Plugin):

    name = "sig"
    description = "Handle PE Signature"

    def add_arguments(self, parser):
        parser.add_argument('--extract', help='Extract the siganture of a PE file to another file' +
            ' in addition to printing info', required=False)
        parser.add_argument('--output', '-o', help='Output file', required=False)
        self.parser = parser

    def get_sig_address(self, pe):
        return pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    def get_sig_info(self, pe, cli_mode=False):

        res = {}
        address = self.get_sig_address(pe)

        if address:
            address = hex(address)
            cli_out("This PE file is signed", cli_mode)
            cli_out("Signature Address: " + address, cli_mode)
            res["address"] = address
        else:
            cli_out("This PE file is not signed", cli_mode)

        return res

    def get_cert_info(self, signature, cli_mode=False):

        def get_name_attr_values(x509_name, sub_object_friendly, res):

            cli_out(sub_object_friendly, cli_mode)
            sub_object = sub_object_friendly.lower()
            if sub_object not in res:
                res[sub_object] = {}

            for name_attr in x509_name:
                friendly_name = OID_NAME_MAP[name_attr.oid]
                key_name = friendly_name.lower().replace(" ", "_")
                value = str(name_attr.value)
                cli_out("\t{:<35} {}".format(friendly_name + ": ", value), cli_mode)
                res[sub_object][key_name] = value

        certificates = []
        for cert in signature["content"]["certificates"]:

            cert_res = {}
            parsed_cert = x509.load_der_x509_certificate(cert.dump(), default_backend())

            # general certificate information
            cli_out(("=" * 100) + "\nCertificate\n" + ("=" * 100) + "\n", cli_mode)

            # certificate version
            version = str(parsed_cert.version)
            cert_res["cert_version"] = version
            cli_out("{:<35} {}".format("Version:", version), cli_mode)

            # validity timestamp boundaries
            not_valid_before = str(parsed_cert.not_valid_before)
            not_valid_after = str(parsed_cert.not_valid_after)
            cert_res["not_valid_before"] = not_valid_before
            cert_res["not_valid_after"] = not_valid_after
            cli_out("{:<35} {}".format("Not Valid Before:", not_valid_before), cli_mode)
            cli_out("{:<35} {}".format("Not Valid After:", not_valid_after), cli_mode)
            cli_out("", cli_mode)

            # issuer information
            get_name_attr_values(parsed_cert.issuer, "Issuer", cert_res)
            cli_out("", cli_mode)

            # subject information
            get_name_attr_values(parsed_cert.subject, "Subject", cert_res)

            cli_out("", cli_mode)
            certificates.append(cert_res)

        # TODO check if cert is valid

        return {"certificates": certificates}

    def get_results(self, pe, cli_mode=False):
        
        res = {}
        res.update(self.get_sig_info(pe, cli_mode))
        if res:
            data = bytes(pe.write()[self.get_sig_address(pe)+8:])
            signature = cms.ContentInfo.load(data)
            cli_out("", cli_mode)
            res.update(self.get_cert_info(signature, cli_mode))
        return {"signature": res} if res else res

    def run_cli(self, args, pe, data):

        self.get_results(pe, cli_mode=True)

        # write the sig to disk
        if args.extract:

            # decide about the path to the extracted sig
            if args.output:
                output = args.output
            else:
                output = args.PEFILE + '.sig'

            # write it
            with open(output, "wb+") as f:
                f.write(data)
