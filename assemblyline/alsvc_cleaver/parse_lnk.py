import struct

LinkFlags_def = ['HasLinkTargetIDList',
                 'HasLinkInfo',
                 'HasName',
                 'HasRelativePath',
                 'HasWorkingDir',
                 'HasArguments',
                 'HasIconLocation',
                 'IsUnicode',
                 'ForceNoLinkInfo',
                 'HasExpString',
                 'RunInSeparateProcess',
                 'Unused1',
                 'HasDarwinID',
                 'RunAsUser',
                 'HasExpIcon',
                 'NoPidlAlias',
                 'Unused2',
                 'RunWithShimLayer',
                 'ForceNoLinkTrack',
                 'EnableTargetMetadata',
                 'DisableLinkPathTracking',
                 'DisableKnownFolderTracking',
                 'DisableKnownFolderAlias',
                 'AllowLinkToLink',
                 'UnaliasOnSave',
                 'PreferEnvironmentPath',
                 'KeepLocalIDListForUNCTarget']

FileAttributes_def = ['FILE_ATTRIBUTE_READONLY',
                      'FILE_ATTRIBUTE_HIDDEN',
                      'FILE_ATTRIBUTE_SYSTEM',
                      'Reserved1',
                      'FILE_ATTRIBUTE_DIRECTORY',
                      'FILE_ATTRIBUTE_ARCHIVE',
                      'Reserved2',
                      'FILE_ATTRIBUTE_NORMAL',
                      'FILE_ATTRIBUTE_TEMPORARY',
                      'FILE_ATTRIBUTE_SPARSE_FILE',
                      'FILE_ATTRIBUTE_REPARSE_POINT',
                      'FILE_ATTRIBUTE_COMPRESSED',
                      'FILE_ATTRIBUTE_OFFLINE',
                      'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
                      'FILE_ATTRIBUTE_ENCRYPTED']

LinkInfoFlags_def = ['VolumeIDAndLocalBasePath',
                     'CNRLAndPathSuffix']

CNRLFlags_def = ['ValidDevice',
                 'ValidNetType']


NetworkProviderType_enum = {
    0x001A0000: 'WNNC_NET_AVID',
    0x001B0000: 'WNNC_NET_DOCUSPACE',
    0x001C0000: 'WNNC_NET_MANGOSOFT',
    0x001D0000: 'WNNC_NET_SERNET',
    0X001E0000: 'WNNC_NET_RIVERFRONT1',
    0x001F0000: 'WNNC_NET_RIVERFRONT2',
    0x00200000: 'WNNC_NET_DECORB',
    0x00210000: 'WNNC_NET_PROTSTOR',
    0x00220000: 'WNNC_NET_FJ_REDIR',
    0x00230000: 'WNNC_NET_DISTINCT',
    0x00240000: 'WNNC_NET_TWINS',
    0x00250000: 'WNNC_NET_RDR2SAMPLE',
    0x00260000: 'WNNC_NET_CSC',
    0x00270000: 'WNNC_NET_3IN1',
    0x00290000: 'WNNC_NET_EXTENDNET',
    0x002A0000: 'WNNC_NET_STAC',
    0x002B0000: 'WNNC_NET_FOXBAT',
    0x002C0000: 'WNNC_NET_YAHOO',
    0x002D0000: 'WNNC_NET_EXIFS',
    0x002E0000: 'WNNC_NET_DAV',
    0x002F0000: 'WNNC_NET_KNOWARE',
    0x00300000: 'WNNC_NET_OBJECT_DIRE',
    0x00310000: 'WNNC_NET_MASFAX',
    0x00320000: 'WNNC_NET_HOB_NFS',
    0x00330000: 'WNNC_NET_SHIVA',
    0x00340000: 'WNNC_NET_IBMAL',
    0x00350000: 'WNNC_NET_LOCK',
    0x00360000: 'WNNC_NET_TERMSRV',
    0x00370000: 'WNNC_NET_SRT',
    0x00380000: 'WNNC_NET_QUINCY',
    0x00390000: 'WNNC_NET_OPENAFS',
    0X003A0000: 'WNNC_NET_AVID1',
    0x003B0000: 'WNNC_NET_DFS',
    0x003C0000: 'WNNC_NET_KWNP',
    0x003D0000: 'WNNC_NET_ZENWORKS',
    0x003E0000: 'WNNC_NET_DRIVEONWEB',
    0x003F0000: 'WNNC_NET_VMWARE',
    0x00400000: 'WNNC_NET_RSFX',
    0x00410000: 'WNNC_NET_MFILES',
    0x00420000: 'WNNC_NET_MS_NFS',
    0x00430000: 'WNNC_NET_GOOGLE',
    None:       'INVALID'
}

showCommand_enum = {
        0x1: 'SW_SHOWNORMAL',
        0x3: 'SW_SHOWMAXIMIZED',
        0x7: 'SW_SHOWMINNOACTIVE',
        None: 'SW_SHOWNORMAL'
    }

def parse_bitmask(mask_def, mask):
    i = 0
    out = []
    while mask != 0:
        if mask & 1:
            try:
                out.append(mask_def[i])
            except IndexError:
                pass
        mask >>= 1
        i += 1
    return out

def parse_enumeration(enum_def, val):
    if val not in enum_def:
        return enum_def[None]
    else:
        return enum_def[val]

def parse_pstr(data, is_utf16):
    n_len, = struct.unpack('<H', data[:2])
    if is_utf16:
        n_len *= 2
    out_str = data[2: 2 + n_len]
    if is_utf16:
        out_str = out_str.decode('utf-16')
    data = data[2 + n_len:]
    return data, out_str


def decode_lnk(lnk, parse_tidlist = False):
    """ See MS-SHLLINK """
    try:
        metadata = {}
        headersize, linkclsid, linkFlags, fileAtributes, ctime, atime, mtime, fsize, iconIndex, showCommand, hotKey, \
            r1, r2, r3 = struct.unpack('<I16sIIQQQIIIHHII', lnk[:76])

        if headersize != 76 or linkclsid != '\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F':
            return None

        showCommand = parse_enumeration(showCommand_enum, showCommand)

        linkFlags = parse_bitmask(LinkFlags_def, linkFlags)
        fileAtributes = parse_bitmask(FileAttributes_def, fileAtributes)

        metadata['showCommand'] = showCommand
        metadata['linkFlags'] = linkFlags
        metadata['fileAtributes'] = fileAtributes

        lnk = lnk[76:]

        is_utf16 = 'IsUnicode' in linkFlags

        if 'HasLinkTargetIDList' in linkFlags:
            ltid_len, = struct.unpack('<H', lnk[:2])
            LinkTargetIDList = lnk[2:ltid_len+2]
            lnk = lnk[ltid_len+2:]

            if parse_tidlist:
                # The spec doesn't give a clear indication of why this is needed.
                # So I've made it optional and disabled by default.
                IDList = [[]]
                while LinkTargetIDList:
                    if LinkTargetIDList[0:2] == '\x00\x00':
                        IDList.append([])
                        LinkTargetIDList = LinkTargetIDList[2:]
                    else:
                        itm_size, = struct.unpack('<H', LinkTargetIDList[0:2])
                        IDList[-1].append(LinkTargetIDList[2:itm_size])
                        LinkTargetIDList = LinkTargetIDList[itm_size:]
                IDList.pop(-1)
                metadata['IDList'] = IDList

        if 'HasLinkInfo' in linkFlags:
            LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset, LocalBasePathOffset, \
                CNRLOffset, CommonPathSuffixOffset = struct.unpack('<IIIIIII', lnk[:28])

            LinkInfo = lnk[:LinkInfoSize]
            lnk = lnk[LinkInfoSize:]

            LinkInfoFlags = parse_bitmask(LinkInfoFlags_def, LinkInfoFlags)

            if 'VolumeIDAndLocalBasePath' in LinkInfoFlags:
                VID = {}
                VolumeIDSize, DriveType, DriveSerialNumber, VolumeLabelOffset, VolumeLabelOffsetUnicode = \
                    struct.unpack('<IIIII', LinkInfo[VolumeIDOffset:VolumeIDOffset+20])
                VID['DriveType'] = ['DRIVE_UNKNOWN', 'DRIVE_NO_ROOT_DIR', 'DRIVE_REMOVABLE', 'DRIVE_FIXED',
                                       'DRIVE_REMOTE', 'DRIVE_CDROM', 'DRIVE_RAMDISK'][DriveType]
                VID['DriveSerialNumber'] = DriveSerialNumber
                VID['VolumeLabel'] = LinkInfo[VolumeIDOffset + VolumeLabelOffset:].split('\x00', 1)[0]

                if VolumeLabelOffset == 0x14:
                    VID['VolumeLabelUnicode'] = LinkInfo[VolumeIDOffset +
                                                         VolumeLabelOffsetUnicode:].split('\x00\x00', 1)[0]
                    VID['VolumeLabelUnicode'] = VID['VolumeLabelUnicode'].decode("utf-16", errors='ignore')

                metadata['BasePath'] = LinkInfo[LocalBasePathOffset:].split('\x00', 1)[0]

                metadata['VolumeID'] = VID

            if 'CNRLAndPathSuffix' in LinkInfoFlags:
                CNRLO = {}
                CNRLSize, CNRLFlags, NetNameOffset, DeviceNameOffset, \
                    NetworkProviderType = struct.unpack("<IIIII", LinkInfo[CNRLOffset:CNRLOffset+20])

                CNRLFlags = parse_bitmask(CNRLFlags_def, CNRLFlags)

                metadata['NetName'] = LinkInfo[CNRLOffset + NetNameOffset:].split('\x00', 1)[0]

                if 'ValidDevice' in CNRLFlags:
                    CNRLO['DeviceName'] = LinkInfo[CNRLOffset + DeviceNameOffset:].split('\x00', 1)[0]

                if 'ValidNetType' in CNRLFlags:
                    CNRLO['NetworkProviderType'] = parse_enumeration(NetworkProviderType_enum, NetworkProviderType)

                if CNRLSize > 0x14:
                    NetNameOffsetUnicode, DeviceNameOffsetUnicode = \
                        struct.unpack("<II", LinkInfo[CNRLOffset + 20:CNRLOffset + 28])

                    CNRLO['NetNameUnicode'] = LinkInfo[CNRLOffset + NetNameOffsetUnicode:].split('\x00\x00', 1)[0]
                    CNRLO['DeviceNameUnicode'] = LinkInfo[CNRLOffset + DeviceNameOffsetUnicode:].split('\x00\x00', 1)[0]
                    CNRLO['NetNameUnicode'] = CNRLO['NetNameUnicode'].decode("utf-16", errors='ignore')
                    CNRLO['DeviceNameUnicode'] = CNRLO['DeviceNameUnicode'].decode("utf-16", errors='ignore')

                metadata['CommonNetworkRelativeLink'] = CNRLO

        # String data
        if 'HasName' in linkFlags:
            lnk, metadata['NAME_STRING'] = parse_pstr(lnk, is_utf16)
        if 'HasRelativePath' in linkFlags:
            lnk, metadata['RELATIVE_PATH'] = parse_pstr(lnk, is_utf16)
        if 'HasWorkingDir' in linkFlags:
            lnk, metadata['WORKING_DIR'] = parse_pstr(lnk, is_utf16)
        if 'HasArguments' in linkFlags:
            lnk, metadata['COMMAND_LINE_ARGUMENTS'] = parse_pstr(lnk, is_utf16)
        if 'HasIconLocation' in linkFlags:
            lnk, metadata['ICON_LOCATION'] = parse_pstr(lnk, is_utf16)

        # Note: there is technically an "ExtraData" block after the strings.
        # But I couldn't find anything in them that was worth parsing out.

        return metadata

    except struct.error:
        # Not enough bytes in the file
        return None


if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as fh:
        print decode_lnk(fh.read())
