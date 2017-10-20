#!/usr/bin/python

import struct
import zlib


class Ole10Native(object):
    def __init__(self, buf):
        offset = 0

        self.rec_length = struct.unpack("<I", buf[offset:offset + 4])[0]
        offset += 4

        self.flags1 = struct.unpack("<H", buf[offset:offset + 2])[0]
        offset += 2

        label_end = buf.find('\x00', offset)
        self.label = buf[offset:label_end]
        offset = label_end + 1

        filename_end = buf.find('\x00', offset)
        self.filename = buf[offset:filename_end]
        offset = filename_end + 1

        self.flags2 = struct.unpack("<H", buf[offset:offset + 2])[0]
        offset += 2

        unknown1_len = struct.unpack("B", buf[offset:offset + 1])[0]
        offset += 1 + unknown1_len

        # unknown2 is 3 bytes
        offset += 3

        command_end = buf.find('\x00', offset)
        self.command = buf[offset:command_end]
        offset = command_end + 1

        self.native_data_size = struct.unpack("<I", buf[offset:offset + 4])[0]
        offset += 4

        self.native_data = buf[offset:offset + self.native_data_size]


class PowerPointDoc(object):
    # Taken DIRECTLY from hachoir-parser - msoffice.pt
    # Credits:
    # Author(s): Robert Xiao, Victor Stinner
    # Creation: 8 January 2005
    OBJ_TYPES = {
        0: "Unknown",
        1000: "Document",
        1001: "DocumentAtom",
        1002: "EndDocument",
        1003: "SlidePersist",
        1004: "SlideBase",
        1005: "SlideBaseAtom",
        1006: "Slide",
        1007: "SlideAtom",
        1008: "Notes",
        1009: "NotesAtom",
        1010: "Environment",
        1011: "SlidePersistAtom",
        1012: "Scheme",
        1013: "SchemeAtom",
        1014: "DocViewInfo",
        1015: "SSlideLayoutAtom",
        1016: "MainMaster",
        1017: "SSSlideInfoAtom",
        1018: "SlideViewInfo",
        1019: "GuideAtom",
        1020: "ViewInfo",
        1021: "ViewInfoAtom",
        1022: "SlideViewInfoAtom",
        1023: "VBAInfo",
        1024: "VBAInfoAtom",
        1025: "SSDocInfoAtom",
        1026: "Summary",
        1027: "Texture",
        1028: "VBASlideInfo",
        1029: "VBASlideInfoAtom",
        1030: "DocRoutingSlip",
        1031: "OutlineViewInfo",
        1032: "SorterViewInfo",
        1033: "ExObjList",
        1034: "ExObjListAtom",
        1035: "PPDrawingGroup",  # FIXME: Office Art File Format Docu
        1036: "PPDrawing",  # FIXME: Office Art File Format Docu
        1038: "Theme",
        1039: "ColorMapping",
        1040: "NamedShows",  # don't know if container
        1041: "NamedShow",
        1042: "NamedShowSlides",  # don't know if container
        1052: "OriginalMainMasterId",
        1053: "CompositeMasterId",
        1054: "RoundTripContentMasterInfo12",
        1055: "RoundTripShapeId12",
        1056: "RoundTripHFPlaceholder12",
        1058: "RoundTripContentMasterId12",
        1059: "RoundTripOArtTextStyles12",
        1060: "HeaderFooterDefaults12",
        1061: "DocFlags12",
        1062: "RoundTripShapeCheckSumForCustomLayouts12",
        1063: "RoundTripNotesMasterTextStyles12",
        1064: "RoundTripCustomTableStyles12",
        2000: "List",
        2005: "FontCollection",
        2017: "ListPlaceholder",
        2019: "BookmarkCollection",
        2020: "SoundCollection",
        2021: "SoundCollAtom",
        2022: "Sound",
        2023: "SoundData",
        2025: "BookmarkSeedAtom",
        2026: "GuideList",
        2028: "RunArray",
        2029: "RunArrayAtom",
        2030: "ArrayElementAtom",
        2031: "Int4ArrayAtom",
        2032: "ColorSchemeAtom",
        3008: "OEShape",
        3009: "ExObjRefAtom",
        3011: "OEPlaceholderAtom",
        3020: "GrColor",
        3024: "GPointAtom",
        3025: "GrectAtom",
        3031: "GRatioAtom",
        3032: "Gscaling",
        3034: "GpointAtom",
        3035: "OEShapeAtom",
        3037: "OEPlaceholderNewPlaceholderId12",
        3998: "OutlineTextRefAtom",
        3999: "TextHeaderAtom",
        4000: "TextCharsAtom",
        4001: "StyleTextPropAtom",
        4002: "BaseTextPropAtom",
        4003: "TxMasterStyleAtom",
        4004: "TxCFStyleAtom",
        4005: "TxPFStyleAtom",
        4006: "TextRulerAtom",
        4007: "TextBookmarkAtom",
        4008: "TextBytesAtom",
        4009: "TxSIStyleAtom",
        4010: "TextSpecInfoAtom",
        4011: "DefaultRulerAtom",
        4023: "FontEntityAtom",
        4024: "FontEmbeddedData",
        4025: "TypeFace",
        4026: "CString",
        4027: "ExternalObject",
        4033: "MetaFile",
        4034: "ExOleObj",
        4035: "ExOleObjAtom",
        4036: "ExPlainLinkAtom",
        4037: "CorePict",
        4038: "CorePictAtom",
        4039: "ExPlainAtom",
        4040: "SrKinsoku",
        4041: "HandOut",
        4044: "ExEmbed",
        4045: "ExEmbedAtom",
        4046: "ExLink",
        4047: "ExLinkAtom_old",
        4048: "BookmarkEntityAtom",
        4049: "ExLinkAtom",
        4050: "SrKinsokuAtom",
        4051: "ExHyperlinkAtom",
        4053: "ExPlain",
        4054: "ExPlainLink",
        4055: "ExHyperlink",
        4056: "SlideNumberMCAtom",
        4057: "HeadersFooters",
        4058: "HeadersFootersAtom",
        4062: "RecolorEntryAtom",
        4063: "TxInteractiveInfoAtom",
        4065: "EmFormatAtom",
        4066: "CharFormatAtom",
        4067: "ParaFormatAtom",
        4068: "MasterText",
        4071: "RecolorInfoAtom",
        4073: "ExQuickTime",
        4074: "ExQuickTimeMovie",
        4075: "ExQuickTimeMovieData",
        4076: "ExSubscription",
        4077: "ExSubscriptionSection",
        4078: "ExControl",
        4080: "SlideListWithText",
        4081: "AnimationInfoAtom",
        4082: "InteractiveInfo",
        4083: "InteractiveInfoAtom",
        4084: "SlideList",
        4085: "UserEditAtom",
        4086: "CurrentUserAtom",
        4087: "DateTimeMCAtom",
        4088: "GenericDateMCAtom",
        4090: "FooterMCAtom",
        4091: "ExControlAtom",
        4100: "ExMediaAtom",
        4101: "ExVideo",
        4102: "ExAviMovie",
        4103: "ExMCIMovie",
        4109: "ExMIDIAudio",
        4110: "ExCDAudio",
        4111: "ExWAVAudioEmbedded",
        4112: "ExWAVAudioLink",
        4113: "ExOleObjStg",
        4114: "ExCDAudioAtom",
        4115: "ExWAVAudioEmbeddedAtom",
        4116: "AnimationInfoAtom",
        4117: "RTFDateTimeMCAtom",
        5000: "ProgTags",  # don't know if container
        5001: "ProgStringTag",
        5002: "ProgBinaryTag",
        5003: "BinaryTagData",
        6000: "PrintOptions",
        6001: "PersistPtrFullBlock",  # don't know if container
        6002: "PersistPtrIncrementalBlock",  # don't know if container
        10000: "RulerIndentAtom",
        10001: "GScalingAtom",
        10002: "GRColorAtom",
        10003: "GLPointAtom",
        10004: "GlineAtom",
        11019: "AnimationAtom12",
        11021: "AnimationHashAtom12",
        14100: "SlideSyncInfo12",
        14101: "SlideSyncInfoAtom12",
        0xf000: "EscherDggContainer",  # Drawing Group Container
        0xf006: "EscherDgg",
        0xf016: "EscherCLSID",
        0xf00b: "EscherOPT",
        0xf001: "EscherBStoreContainer",
        0xf007: "EscherBSE",
        0xf018: "EscherBlip_START",  # Blip types are between
        0xf117: "EscherBlip_END",  # these two values
        0xf002: "EscherDgContainer",  # Drawing Container
        0xf008: "EscherDg",
        0xf118: "EscherRegroupItems",
        0xf120: "EscherColorScheme",  # bug in docs
        0xf003: "EscherSpgrContainer",
        0xf004: "EscherSpContainer",
        0xf009: "EscherSpgr",
        0xf00a: "EscherSp",
        0xf00c: "EscherTextbox",
        0xf00d: "EscherClientTextbox",
        0xf00e: "EscherAnchor",
        0xf00f: "EscherChildAnchor",
        0xf010: "EscherClientAnchor",
        0xf011: "EscherClientData",
        0xf005: "EscherSolverContainer",
        0xf012: "EscherConnectorRule",  # bug in docs
        0xf013: "EscherAlignRule",
        0xf014: "EscherArcRule",
        0xf015: "EscherClientRule",
        0xf017: "EscherCalloutRule",
        0xf119: "EscherSelection",
        0xf11a: "EscherColorMRU",
        0xf11d: "EscherDeletedPspl",  # bug in docs
        0xf11e: "EscherSplitMenuColors",
        0xf11f: "EscherOleObject",
        0xf122: "EscherUserDefined"
    }

    def __init__(self, buf):
        self.size = len(buf)
        if self.size <= 512:
            raise BaseException("Buffer is too small.")
        self.objects = []

        cur_iter = 0
        while cur_iter < self.size:
            pp_obj = PowerPointObject(buf[cur_iter:])
            self.objects.append(pp_obj)
            cur_iter += pp_obj.length


# Represents an object stream within the PowerPoint Document Stream
# Will decompress ExOleObjStg objects
class PowerPointObject(object):
    # noinspection PyBroadException
    def __init__(self, buf):
        self.rec_ver = struct.unpack("B", buf[0])[0] & 0xF
        self.rec_instance = struct.unpack("<H", buf[:2])[0] >> 4
        self.rec_type = PowerPointDoc.OBJ_TYPES[struct.unpack("<H", buf[2:4])[0]]
        self.rec_length = struct.unpack("<I", buf[4:8])[0]
        self.length = self.rec_length + 8
        self.raw = buf[0x8:0x8 + self.rec_length]
        self.error = None

        if self.rec_type == "ExOleObjStg":
            if self.rec_instance == 0x001:
                self.compressed = True
                compressed_size = self.rec_length - 4
                compressed_buffer = buf[12:12 + compressed_size]
                try:
                    z = zlib.decompressobj()
                    self.raw = z.decompress(compressed_buffer)
                except Exception as ex:
                    self.error = "Error decompressing the stream: {}\n".format(ex)
            else:
                self.compressed = False


if __name__ == "__main__":
    import sys
    import hashlib

    with open(sys.argv[1], 'r') as fh:
        data = fh.read()

    print("Total Size: {}\n".format(len(data)))
    # noinspection PyBroadException
    try:
        pp_doc = PowerPointDoc(data)
        for obj in pp_doc.objects:
            print("Version: {}\nInstance: {}\nType: {}\nLength: {}\nHead: {}\n".format(
                hex(obj.rec_ver), hex(obj.rec_instance), obj.rec_type, obj.rec_length,
                repr(obj.raw[:min(len(obj.raw), 32)])
            ))
            if obj.rec_type == "ExOleObjStg":
                if obj.compressed:
                    print("Decompressed: {}\n".format(
                        repr(obj.decompressed_raw[:min(len(obj.decompressed_raw), 32)])
                    ))
                fname = "/tmp/{}.pp_obj".format(hashlib.sha256(obj.decompressed_raw).hexdigest())
                with open(fname, 'w') as fh:
                    fh.write(obj.decompressed_raw)
    except:
        pass

    try:
        ole10 = Ole10Native(data)
        print("Length: {}\nLabel: {}\nFilename: {}\nData Length: {}\nData: {}\n".format(
            ole10.rec_length, ole10.label, ole10.filename, ole10.native_data_size,
            ole10.native_data[:min(len(ole10.native_data), 32)]
        ))
    except Exception as e:
        print("Unable to create Ole10Native: {}".format(e))
