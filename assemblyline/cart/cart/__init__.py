import sys

if sys.version_info[0] == 3:
    from cart.cart import main, pack_stream, unpack_stream, pack_file, unpack_file, get_metadata_only, is_cart, \
        MANDATORY_HEADER_FMT, MANDATORY_FOOTER_FMT, DEFAULT_ARC4_KEY
else:
    from cart import main, pack_stream, unpack_stream, pack_file, unpack_file, get_metadata_only, is_cart, \
        MANDATORY_HEADER_FMT, MANDATORY_FOOTER_FMT, DEFAULT_ARC4_KEY