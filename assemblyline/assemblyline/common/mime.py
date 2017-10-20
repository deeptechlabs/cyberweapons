import quopri
import base64


# noinspection PyBroadException
def get_mime_encoded_word_in_unicode(string):
    # we are looking for: '=?charset?encoding?encoded text?='

    decoded_text = None
    unicode_text = None
    try:
        if string.startswith('=?') and '?=' in string:
            string = string[:string.find("?=") + len("?=")]
            if string.count('?') == 4:
                charset_start_index = 2
                encoding_start_index = charset_start_index + 1 + string[charset_start_index + 1:].find('?') + 1
                encoded_text_start_index = encoding_start_index + string[encoding_start_index:].find('?') + 1

                charset = string[charset_start_index:encoding_start_index - 1]
                encoding = string[encoding_start_index: encoded_text_start_index - 1]
                encoded_text = string[encoded_text_start_index:-2]

                if encoding == 'Q':
                    decoded_text = quopri.decodestring(encoded_text, True)
                elif encoding == 'B':
                    decoded_text = base64.b64decode(encoded_text)

                if decoded_text is not None:
                    unicode_text = unicode(decoded_text, charset)

    except:  # pylint:disable=W0702
        # if anything goes wrong, simply return None
        return None

    return unicode_text
