from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT
from assemblyline.al.service.base import ServiceBase

import json


class Characterize(ServiceBase):
    """ Basic File Characterization.

    Currently characterize only generates file partition entropy data.
    """

    SERVICE_ACCEPTS = '.*'
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_DESCRIPTION = "Partitions the file and calculates visual entropy for each partition."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.25
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(Characterize, self).__init__(cfg)

    def execute(self, request):
        path = request.download()
        with open(path, 'rb') as fin:
            (entropy, part_entropies) = calculate_partition_entropy(fin)

        entropy_graph_data = {
            'type': 'colormap',
            'data': {
                'domain': [0, 8],
                'values': part_entropies
            }
        }
        section = ResultSection(
            SCORE.NULL, 
            'Entropy.\tEntire File: {}'.format(round(entropy, 3)),
            self.SERVICE_CLASSIFICATION,
            body_format=TEXT_FORMAT.GRAPH_DATA,
            body=json.dumps(entropy_graph_data))
        result = Result()
        result.add_section(section)
        request.result = result
