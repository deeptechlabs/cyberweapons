from assemblyline.common.context import Context
from assemblyline.common.hexdump import hexdump
from assemblyline.al.common.result import Result, ResultSection, Classification
from assemblyline.al.common.result import SCORE, TEXT_FORMAT, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase, UpdaterType, UpdaterFrequency

import json
import random
import tempfile


class ResultSample(ServiceBase):
    """
    This service generates fake data to showcase
    the different features of the AL Result object
    """

    SERVICE_ACCEPTS = '.*'
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'

    def __init__(self, cfg=None):
        super(ResultSample, self).__init__(cfg)

    def execute(self, request):
        # Create a result object where all the sections will be stored
        result = Result()

        # ==================================================================
        # Default Section:
        #     Default section basically just dumps the text to the screen...
        #       All sections scores will be SUMed in the service result
        #       The Result classification will be the highest classification found in the sections
        default_section = ResultSection(
            SCORE.LOW,
            'Example of a default section',
            Classification.RESTRICTED)
        default_section.add_line("You can add line by line!")
        default_section.add_lines(["Or", "Multiple lines", "Inside a list!"])

        # ==================================================================
        # Color map Section:
        #     Creates a color map bar using a minimum and maximum domain
        cmap_min = 0
        cmap_max = 20
        color_map_data = {
            'type': 'colormap',
            'data': {
                'domain': [cmap_min, cmap_max],
                'values': [random.random() * cmap_max for _ in xrange(50)]
            }
        }
        section_color_map = ResultSection(
            SCORE.NULL,
            "Example of colormap result section",
            self.SERVICE_CLASSIFICATION,
            body_format=TEXT_FORMAT.GRAPH_DATA,
            body=json.dumps(color_map_data))

        # ==================================================================
        # URL section:
        #     Generate a list of clickable urls using a json encoded format
        url_section = ResultSection(
            SCORE.NULL,
            'Example of a simple url section',
            self.SERVICE_CLASSIFICATION,
            body_format=TEXT_FORMAT.URL,
            body=json.dumps({"name": "Google", "url": "https://www.google.com/"}))

        # You can add tags to any section although those tag will be brought up to the result object
        #     Tags are defined by a type, value and weight (confidence lvl)
        #         you can also add a classification and context if needed
        url_section.add_tag(TAG_TYPE.NET_DOMAIN_NAME, "google.com", TAG_WEIGHT.LOW)
        url_section.add_tag(TAG_TYPE.NET_DOMAIN_NAME, "bob.com", TAG_WEIGHT.LOW,
                            classification=Classification.RESTRICTED)
        url_section.add_tag(TAG_TYPE.NET_DOMAIN_NAME, "baddomain.com",
                            TAG_WEIGHT.LOW, context=Context.BEACONS)

        # You may also want to provide a list of url! Also, No need to provide a name, the url link will be displayed
        urls = [{"url": "https://google.com/"}, {"url": "https://google.ca/"}, {"url": "https://microsoft.com/"}]
        url_section2 = ResultSection(
            SCORE.MED,
            'Example of a url section with multiple links',
            self.SERVICE_CLASSIFICATION,
            body_format=TEXT_FORMAT.URL,
            body=json.dumps(urls))
        # Add url_section2 as a subsection of url section
        #     The score of the subsections will automatically be added to the parent section
        url_section.add_section(url_section2)

        # ==================================================================
        # Memory dump section:
        #     Dump whatever string content you have into a <pre/> html tag so you can do your own formatting
        data = hexdump("This is some random text that we will format as an hexdump and you'll see "
                       "that the hexdump formatting will be preserved by the memory dump section!")
        memdump_section = ResultSection(
            SCORE.NULL,
            'Example of a memory dump section',
            self.SERVICE_CLASSIFICATION,
            body_format=TEXT_FORMAT.MEMORY_DUMP,
            body=data)

        # ==================================================================
        # Re-Submitting files to the system
        #     Adding extracted files will have them resubmitted to the system for analysis
        if request.srl != '8cf8277a71e85122bf7ea4610c7cfcc0bfb6dee799be50a41b2f4b1321b3317f':
            # This IF just prevents resubmitting the same file in a loop for this exemple...
            temp_path = tempfile.mktemp(dir=self.working_directory)
            with open(temp_path, "w") as myfile:
                myfile.write(data)
            request.add_extracted(temp_path, "Extracted by some random magic!", display_name="file.txt")

        # ==================================================================
        # Supplementary files
        #     Adding supplementary files will save them on the datastore for future
        #      reference but wont reprocess those files.
        temp_path = tempfile.mktemp(dir=self.working_directory)
        with open(temp_path, "w") as myfile:
            myfile.write(json.dumps(urls))
        request.add_supplementary(temp_path, "These are urls as a JSON", display_name="urls.json")

        # ==================================================================
        # Wrap-up:
        #     Add all sections to the Result object
        result.add_section(default_section)
        result.add_section(section_color_map)
        result.add_section(url_section)
        result.add_section(memdump_section)
        request.result = result

    def start(self):
        # ==================================================================
        # On Startup actions:
        #     Your service might have to do so warmup on startup to make things faster
        #       or simply register an updater function to keep it up to date.

        # Here is a example of registering an updater function
        # Parameters are:
        #       func: The callback funtion (function called at each interval)
        #       blocking: Do we have to block processing while the update takes place? (Default: False)
        #       execute_now: Should we run the updater while registering it? (Default: True)
        #       utype: Type of update
        #               PROCESS is only for current process,
        #               BOX only one update per physical/virtual machine
        #               CLUSTER only one update for the full cluster (Default: PROCESS)
        #       freq: Frequency at which the update takes place(Default: HOURLY)
        self._register_update_callback(self.update, blocking=True, execute_now=False,
                                       utype=UpdaterType.PROCESS, freq=UpdaterFrequency.MINUTE)

    def update(self, *args, **kwargs):
        # ==================================================================
        # This is a sample update callback function
        #       NOTE: all update callback functions must be able to receive *args and **kwargs.
        import time

        runtime = 5
        self.log.info("Updater started... args=%s, kwargs=%s" % (args, kwargs))
        time.sleep(runtime)
        self.log.info("Updater ran for %s seconds..." % runtime)
