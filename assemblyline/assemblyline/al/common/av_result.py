
from assemblyline.al.common.result import ResultSection, Tag, TAG_WEIGHT, Classification, TAG_USAGE, TAG_TYPE


class VirusHitSection(ResultSection):
    def __init__(self, virus_name, score, embedded_filename='', detection_type=''):
        if embedded_filename:
            title = 'Embedded file: %s was identified as %s' % (
                    embedded_filename, virus_name)
        else:
            title = 'File was identified as %s' % virus_name

        if detection_type:
            title += ' (%s)' % detection_type

        super(VirusHitSection, self).__init__(
            title_text=title,
            score=score,
            classification=Classification.UNRESTRICTED)


class VirusHitTag(Tag):
    def __init__(self, virus_name, context=None):
        super(VirusHitTag, self).__init__(
            tag_type=TAG_TYPE.AV_VIRUS_NAME,
            value=virus_name,
            weight=TAG_WEIGHT.MED,
            usage=TAG_USAGE.IDENTIFICATION,
            classification=Classification.UNRESTRICTED,
            context=context)

class AvScanResult(object):

    RESULT_OK = 'ok'

    def __init__(self): 
        self.application_name = ''
        self.version_application = ''
        self.version_dats = ''
        self.version_engine = ''
        self.results = {}

    def add_result(self, file_path, is_virus, virus_name, detection_type='', embedded_file=''):
        # Empty embedded file indicates the original file itself (non embedded result).
        if file_path not in self.results:
            self.results[file_path] = {}
        self.results[file_path][embedded_file] = (is_virus, detection_type, virus_name, '')

    def get_result(self, file_path):
        self.results.get(file_path, None)

    def __str__(self):
        from cStringIO import StringIO
        from pprint import pformat
        output = StringIO()
        output.write('result:%s - %s - %s\n' % (
            self.version_application, self.version_dats, self.version_engine))
        output.write('\n%s' % pformat(self.results))
        result = output.getvalue()
        output.close()
        return result


