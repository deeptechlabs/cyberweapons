import json
import os

from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
import hashlib
import time


class TorrentSlicer(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'meta/torrent'
    SERVICE_DESCRIPTION = "Extracts information from torrent files"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(TorrentSlicer, self).__init__(cfg)

    def start(self):
        self.log.debug("TorrentSlicer service started")

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global bencode, binascii, humanfriendly, size, si
        from hurry.filesize import size, si
        import bencode
        import binascii
        import humanfriendly

    # noinspection PyUnusedLocal
    @staticmethod
    def create_tables(infohash,
                      announce,
                      announce_list,
                      creation_date,
                      comment,
                      created_by,
                      encoding,
                      piece_length,
                      private,
                      name,
                      sflength,
                      sfmd5sum,
                      files,
                      piecehashes,
                      last_piece_size,
                      torrent_size,
                      torrent_type):

        announce_str = ""
        for x in announce_list:
            for y in x:
                announce_str += "{} " .format(y)

        meta_dict = {
            'InfoHash:': infohash,
            'Announce:': announce,
            'Announce List*:': announce_str,
            'Creation Date*:': creation_date,
            'Comment*:': comment,
            'Created By*:': created_by,
            'Encoding*:': encoding,
            'Piece Length:': "%s (%s)" % (str(piece_length), size(piece_length, system=si)),
            'Private*:': private,
            'Name*:': name,
        }

        meta = []
        for k, i in sorted(meta_dict.iteritems()):
            meta.append('{0:20s} {1}' .format(k, i))

        cal_dict = {
            'Type of Torrent:': torrent_type,
            'Number of Pieces:': str(len(piecehashes)),
            'Last Piece Size:': "%s (%s)" % (str(last_piece_size), size(last_piece_size, system=si)),
            'Size of Torrent:': "%s (%s)" % (str(torrent_size), size(torrent_size, system=si)),
        }

        cal = []
        for k, i in sorted(cal_dict.iteritems()):
            cal.append('{0:18s} {1}' .format(k, i))

        des = []
        if len(files) > 0:
            des.append('{:100s} {:10s} {:32s}' .format('File Path', 'Length', 'MD5Sum*'))
            des.append('{:100s} {:10s} {:32s}' .format('-' * 9, '-' * 6, '-' * 7))
            for f in files:
                fmd5 = ""
                path = ""
                for k, i in f.iteritems():
                    if k == "hash":
                        fmd5 = i
                    if k == "path":
                        for x in i:
                            path = str(x)
                des.append('{:100s} {:10s} {:32s}' .format(path, size(f['length'], system=si), fmd5))

        return meta, cal, des

    def run_tosl(self, filename, request):
        file_res = request.result

        torrent_file = open(filename, "rb").read()

        # noinspection PyBroadException
        try:
            metainfo = bencode.bdecode(torrent_file)
        except:
            res = (ResultSection(SCORE.NULL, "This is not a valid *.torrent file"))
            file_res.add_result(res)
            return

        # Grab specific data from file

        announce = metainfo['announce']
        if 'announce-list' in metainfo:
            announce_list = metainfo['announce-list']
        else:
            announce_list = ""
        if 'creation date' in metainfo:
            creation_date = metainfo['creation date']
        else:
            creation_date = ""
        if 'comment' in metainfo:
            comment = metainfo['comment']
        else:
            comment = ""
        if 'created by' in metainfo:
            created_by = metainfo['created by']
        else:
            created_by = ""
        if 'encoding' in metainfo:
            encoding = metainfo['encoding']
        else:
            encoding = ""
        if 'url-list' in metainfo:
            url_list = metainfo['url-list']
        else:
            url_list = []

        info = metainfo['info']
        piece_length = info['piece length']
        pieces = info['pieces']
        if 'private' in info:
            private = info['private']
        else:
            private = ""
        if 'name' in info:
            name = info['name']
        else:
            name = ""
        if 'length' in info:
            sflength = info['length']
        else:
            sflength = ""
        if 'md5sum' in info:
            sfmd5sum = info['md5sum']
        else:
            sfmd5sum = ""
        if 'files' in info:
            files = info['files']
        else:
            files = []

        infohash = hashlib.sha1(bencode.bencode(info)).hexdigest()
        piecehashes = [binascii.hexlify(pieces[i:i+20]) for i in range(0, len(pieces), 20)]
        torrent_size = 0

        for i in files:
            torrent_size += i['length']
            i['length'] = i['length']
            for j in range(len(i['path'])):
                i['path'][j] = unicode(i['path'][j], "utf8")

        if torrent_size == 0:
            torrent_type = 'single file torrent'
            torrent_size = sflength
        else:
            torrent_type = 'multiple file torrent'

        last_piece_size = min(torrent_size, (len(piecehashes) * int(piece_length)) - torrent_size)

        errmsg = []
        if last_piece_size > piece_length:
            errmsg.append("WARNING: The calculated length of the last piece is greater than the stated piece length")
        if (piece_length > torrent_size) and (torrent_type == 'multiple file torrent'):
            errmsg.append("WARNING: The stated length of an individual piece is greater "
                          "than the calculated torrent size")

        if creation_date != "":
            creation_date_conv = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(creation_date))
            creation_date_str = "{0} ({1})" .format(str(creation_date), creation_date_conv)
        else:
            creation_date_str = creation_date

        # Generate result output
        meta, cal, des = self.create_tables(
            infohash,
            announce,
            announce_list,
            creation_date_str,
            comment,
            created_by,
            encoding,
            piece_length,
            private,
            name,
            sflength,
            sfmd5sum,
            files,
            piecehashes,
            last_piece_size,
            torrent_size,
            torrent_type
        )

        tosl_res = (ResultSection(SCORE.NULL, "Torrent File Details"))
        comment = "NOTE: '*' Denotes an optional field in the Torrent Descriptor File. As a result it may be blank. " \
                  "Refer to the BitTorrent Specification.\n"
        tosl_res.add_line(comment)

        if len(errmsg) > 0:
            error_res = (ResultSection(SCORE.NULL, "Errors Detected:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                       parent=tosl_res))
            for line in errmsg:
                error_res.add_line(line)

        meta_res = (ResultSection(SCORE.NULL, "Meta Data:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                  parent=tosl_res))
        for line in meta:
            meta_res.add_line(line)

        cal_res = (ResultSection(SCORE.NULL, "Calculated Data:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                 parent=tosl_res))
        comment = "NOTE: the length of last piece is calculated as:" \
                  "(number of pieces X piece length) - size of torrent\n"
        cal_res.add_line(comment)
        for line in cal:
            cal_res.add_line(line)

        if len(des) > 0:
            des_res = (ResultSection(SCORE.NULL, "File paths:",
                                     body_format=TEXT_FORMAT.MEMORY_DUMP, parent=tosl_res))
            for line in des:
                des_res.add_line(line)

        if url_list:
            url_res = (ResultSection(SCORE.NULL, "Urls found in metadata:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                     parent=tosl_res))
            for url in url_list:
                url_res.add_line(url)
                url_res.add_tag(TAG_TYPE['NET_FULL_URI'], url, TAG_WEIGHT.LOW)

        sha1_hashes = os.path.join(self.working_directory, "hash_of_pieces.json")
        with open(sha1_hashes, "wb") as sha1_file:
            sha1_file.write(json.dumps(piecehashes))

        request.add_supplementary(sha1_hashes, "List of hashes in order of the different pieces of the torrent (json)")

        # Tags
        if len(announce) > 0:
            tosl_res.add_tag(TAG_TYPE['NET_FULL_URI'], announce, TAG_WEIGHT.LOW)

        for it in announce_list:
            for uri in it:
                tosl_res.add_tag(TAG_TYPE['NET_FULL_URI'], uri, TAG_WEIGHT.LOW)

        if name != "":
            tosl_res.add_tag(TAG_TYPE['FILE_NAME'], name, TAG_WEIGHT.LOW)

        for f in files:
                for k, i in f.iteritems():
                    if k == "hash" and len(k) > 0:
                        tosl_res.add_tag(TAG_TYPE['FILE_MD5'], i, TAG_WEIGHT.LOW)
                    if k == "path" and len(k) > 0:
                        for x in i:
                            tosl_res.add_tag(TAG_TYPE['FILE_NAME'], str(x), TAG_WEIGHT.LOW)

        file_res.add_result(tosl_res)

    def execute(self, request):
        request.result = Result()
        local_path = request.download()
        self.run_tosl(local_path, request)
