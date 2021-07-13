def hex_reverse(integer, size):
    """
    Reverse a hex string, bf99 -> 99bf
    """
    string = '{0:0{1}x}'.format(integer, size)
    return ''.join([string[i-2:i] for i in range(len(string), 0, -2)])

def debug_filename(pe):
    """
    Extract filename from a PE file
    """
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for i in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(i.entry, 'PdbFileName'):
                return i.entry.PdbFileName.decode('utf-8', 'ignore')
    return None

def debug_guid(pe):
    """
    Extract Debug GUID from a PE file
    """
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        for i in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(i.entry, 'Signature_Data1'):
                return '{:08x}-{:04x}-{:-4x}-{}-{}{}'.format(
                    i.entry.Signature_Data1,
                    i.entry.Signature_Data2,
                    i.entry.Signature_Data3,
                    hex_reverse(i.entry.Signature_Data4, 4),
                    hex_reverse(i.entry.Signature_Data5, 4),
                    hex_reverse(i.entry.Signature_Data6, 8)
                )
    return None

def search_section(pe, address, physical=True):
    """Search the section of the address (return None if not found)"""
    if physical:
        for s in pe.sections:
            if (address >= s.PointerToRawData) and (address <= s.PointerToRawData + s.SizeOfRawData):
                #vaddr = pe.OPTIONAL_HEADER.ImageBase + pos - s.PointerToRawData + s.VirtualAddress
                return s.Name.decode('utf-8', 'ignore').strip('\x00')
    else:
        for s in pe.sections:
            if (address >= (pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress)) and (address <= (pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress + s.Misc_VirtualSize)):
                return s.Name.decode('utf-8', 'ignore').strip('\x00')

    return "unknown"

def cli_out(msg, cli_mode):
    """
    Print the message to stdout if cli_mode is True
    """
    if cli_mode:
        print(msg)