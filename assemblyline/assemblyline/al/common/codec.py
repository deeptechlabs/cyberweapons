import os
import tempfile

from assemblyline.common import identify

NEUTERED_FORMAT = [
    'archive/cart'
]

def decode_file(original_path, fileinfo):
    extracted_path = None
    original_name = None
    al_meta = {}
    if fileinfo['tag'] in NEUTERED_FORMAT:
        from cart import unpack_stream

        extracted_fd, extracted_path = tempfile.mkstemp()
        extracted_file = os.fdopen(extracted_fd, 'wb')

        original_file = open(original_path)

        hdr, _ = unpack_stream(original_file, extracted_file)
        original_name = hdr.get('name', os.path.basename(original_path))
        al_meta = hdr.get("al", {}).get("meta", {})

        extracted_file.close()
        fileinfo = identify.fileinfo(extracted_path)
        if original_name:
            fileinfo['path'] = original_name

    return extracted_path, original_name, fileinfo, al_meta


# noinspection PyUnusedLocal
def encode_file(data, file_format, name, password=None):
    error = {}
    already_encoded = False

    file_info = identify.ident(data, len(data))

    if file_info['tag'] in NEUTERED_FORMAT:
        already_encoded = True
    elif file_format == 'cart':
        from cart import pack_stream
        from cStringIO import StringIO
        ostream = StringIO()
        pack_stream(StringIO(data), ostream, {"name": name})
        data = ostream.getvalue()
    elif file_format != 'raw':
        error['code'] = 500
        error['text'] = "Invalid file format specified."

    return data, error, already_encoded


