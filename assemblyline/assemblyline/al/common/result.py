import logging

from assemblyline.common.context import Context
from assemblyline.common.charset import safe_str
from assemblyline.common.strutil import StringTable, NamedConstants
from assemblyline.al.common.forge import get_constants
from assemblyline.al.common import forge
from assemblyline.al.common.heuristics import Heuristic

constants = get_constants()

import traceback

Classification = forge.get_classification()

TEXT_FORMAT = StringTable('TEXT_FORMAT', [
    ('MEMORY_DUMP', 3),
    ('GRAPH_DATA', 4),
    ('URL', 5),
])

TAG_USAGE = StringTable('TAG_USAGE', [
    ('CORRELATION', 0),
    ('IDENTIFICATION', 1),
    ('IGNORE', 2),
])


SCORE = NamedConstants('SCORE', [
    ('SURE', 1000),  # Malware.
    ('VHIGH', 500),  # This is most likely malware.
    ('HIGH', 100),   # This really looks like malware.
    ('MED', 50),     # Has malware characteristics rarely seen in other apps.
    ('LOW', 10),     # Has malware characteristics also seen in legit apps.
    ('INFO', 1),
    ('NULL', 0),
    ('OK', -100),
    ('NOT', -1000)   # NOT malware.
])


TAG_WEIGHT = NamedConstants('TAG_WEIGHT', [
    ('SURE', 50),
    ('VHIGH', 40),
    ('HIGH', 25),
    ('MED', 10),
    ('LOW', 1),
    ('NULL', 0),
])

TAG_SCORE = TAG_WEIGHT

TAG_TYPE = StringTable('TAG_TYPE', constants.STANDARD_TAG_TYPES)

DBT = StringTable('DBT', [
    ('Alters Windows Firewall', 0),
    ('Checks For Debugger', 1),
    ('Copies to Windows', 2),
    ('Could Not Load', 3),
    ('Creates DLL in System', 4),
    ('Creates EXE in System', 5),
    ('Creates Hidden File', 6),
    ('Creates Mutex', 7),
    ('Creates Service', 8),
    ('Deletes File in System', 10),
    ('Deletes Original Sample', 11),
    ('Hooks Keyboard', 12),
    ('Injected Code', 13),
    ('Makes Network Connection', 14),
    ('Modifies File in System', 15),
    ('Modifies Local DNS', 16),
    ('More than 5 Processes', 17),
    ('Opens Physical Memory', 18),
    ('Starts EXE in Documents', 19),
    ('Starts EXE in Recycle', 20),
    ('Starts EXE in System', 21),
    ('Windows/Run Registry Key Set)', 22)
])

# please reuse those.  This is meant to be a summary so, if we have different tags for the same thing,
# it won't be a summary anymore.
FILE_SUMMARY = StringTable('FILE_SUMMARY', constants.FILE_SUMMARY)

log = logging.getLogger('assemblyline.svc.common.result')


class Tag(object):

    def __init__(self, tag_type, value, weight,
                 usage=TAG_USAGE.IDENTIFICATION,
                 classification=Classification.UNRESTRICTED,
                 context=None):

        self.tag_type = tag_type
        self.value = value
        self.weight = weight
        self.usage = usage
        self.classification = classification
        self.context = context


class ResultSection(dict):

    """
    ResultSections behave like a dict with convenience methods for creating
    UI-friendly section structures:

    ResultSection:
        title_text            ---    title text
        score                 ---    aggregate score of the section content
        classification        ---    classification of section content
        parent                ---    if this section is a subsection, it will have a parent
        body                  ---    section body
        body_format           ---    format of the body
        subsections           ---    children of this section
        depth                 ---    section depth relative to root section
                                     this will be 0 if we are a root section
    """

    # Used to enforce a static section field set
    allowed = ('classification',
               'score',
               'title_text',
               'body',
               'body_format',
               'links',
               'file_id',
               'subsections',
               'depth',
               'parent',
               'finalized',
               'tags',
               'truncated')

    def __init__(self,
                 score=0,
                 title_text=None,
                 classification=Classification.UNRESTRICTED,
                 parent=None,
                 body='',
                 body_format=None,
                 tags=None,
                 ):
        super(ResultSection, self).__init__()
        self.parent = parent
        self.score = score
        self.classification = classification
        self.body = body
        self.body_format = body_format
        self.links = []
        self.subsections = []
        self.tags = tags or []
        self.depth = 0
        self.finalized = False
        self.truncated = False
        if isinstance(title_text, list):
            title_text = ''.join(title_text)
        self.title_text = safe_str(title_text)
 
        if parent is not None:
            parent.add_section(self)

        self._warn_on_validation_errors()

    def _warn_on_validation_errors(self):
        if not (isinstance(self.score, int) and 2000 >= self.score >= -1000):
            log.warn("invalid score: %s", str(self.score))
        if not Classification.is_valid(self.classification):
            tb = traceback.format_stack(limit=4)
            log.warn("invalid classification:%s.\n%s", str(self.classification), str(tb))
        if not isinstance(self.title_text, basestring):
            log.warn("invalid type for titletext: %s", type(self.title_text))
        if not isinstance(self.body, basestring):
            log.warn("invalid type for body: %s", type(self.body))

    def set_body(self, body, body_format=None):
        self.body = body
        if body_format is not None:
            self.body_format = body_format

    def add_lines(self, line_list):
        if not isinstance(line_list, list):
            log.warn("add_lines call with invalid type: %s. ignoring", type(line_list))
            return

        segment = '\n'.join(line_list)
        if len(self.body) == 0:
            self.body = segment
        else:
            self.body = self.body + '\n' + segment

    def add_line(self, text, _deprecated_format=None):
        # add_line with a list should join without newline seperator.
        # use add_lines if list should be split one element per line.
        if isinstance(text, list):
            text = ''.join(text)
        textstr = safe_str(text)
        if len(self.body) != 0:
            # noinspection PyAugmentAssignment
            textstr = '\n' + textstr
        self.body = self.body + textstr

    def add_tag(self, tag_type, value, weight, usage=None,
                classification=Classification.UNRESTRICTED, context=None):
        tag = {'type': tag_type, 'value': safe_str(value), 'weight': weight, 'usage': usage,
               'classification': classification, 'context': context}

        for existing_tag in self.tags:
            if existing_tag['type'] == tag['type'] and \
               existing_tag['value'] == tag['value']:
                return
        self.tags.append(tag)

        if not TAG_TYPE.contains_value(tag_type):
            log.warn("Invalid tag_type: %s", tag_type)
        if len(value) <= 0 or len(value) >= 2048:
            log.warn("invalid tag_value: %s:'%s'", tag_type, safe_str(value))
        if not (isinstance(weight, int) and -1000 < weight < 1000):
            log.warn("invalid weight: %s", weight)
        if usage and not TAG_USAGE.contains_value(usage):
            log.warn("invalid tag usage: %s", usage)
        if not Classification.is_valid(classification):
            tb = traceback.format_stack(limit=4)
            log.warn("invalid classification:%s.\n%s", str(self.classification), str(tb))
        if context:
            if not Context.verify_context(tag_type, context):
                log.warn("Invalid tag_type: %s and context: %s combination" % (tag_type, context))

    def change_score(self, new_score):
        self.score = new_score

    def add_section(self, section, on_top=False):
        if on_top:
            self.subsections.insert(0, section)
        else:
            self.subsections.append(section)
        section.parent = self

    def finalize(self, depth=0):

        if self.finalized:
            raise Exception("Double finalize() on result detected.")
        self.finalized = True

        keep_me = True
        tmp_subs = []
        self.depth = depth
        for subsection in self.subsections:
            subsection.finalize(depth=depth + 1)
            # Unwrap it if we're going to keep it
            if subsection in self.subsections:
                tmp_subs.append(subsection)
        self.subsections = tmp_subs
        # At this point, all subsections are finalized and we're not deleting ourself
        if self.parent is not None:
            self.parent.classification = \
                Classification.max_classification(self.classification, self.parent.classification)
            self.parent.score += self.score
            for tag in self.tags:
                self.parent.add_tag(tag['type'], tag['value'], tag['weight'], usage=tag['usage'],
                                    classification=tag['classification'], context=tag['context'])
        self.pop('tags')
        self.pop('parent')
        return keep_me

    def __getattribute__(self, attr):
        if attr in self:
            return self[attr]
        else:
            return dict.__getattribute__(self, attr)

    def __setattr__(self, attr, val):
        if attr not in self.allowed:
            raise Exception('This field is not valid in a ResultSection: %s' % attr)
        self[attr] = val


class Result(dict):

    """
    Top-level service result wrapper, some convenience methods for
    adding tags, subsections, etc.

    Result:
        tags             ---    file tags
        tags_score       ---    aggregate score of the tags
        classification   ---    service classification based on results
        score            ---    aggregate score of the section scores
        sections         ---    the service will invoke add_section
    """

    allowed = ('tags',
               'tags_score',
               'classification',
               'score',
               'file_id',
               'sections',
               'filename',
               'status',
               'order_by_score',
               'default_usage',
               'truncated',
               'context')

    def __init__(self,
                 tags=None,
                 classification=Classification.UNRESTRICTED,
                 score=0,
                 sections=None,
                 default_usage=None
                 ):
        super(Result, self).__init__()
        self.tags = tags or []
        self.tags_score = 0
        self.classification = classification
        self.score = score
        self.sections = sections or []
        self.order_by_score = False
        self.default_usage = default_usage
        self.truncated = False
        self.context = None

    def append_tag(self, tag):
        assert(isinstance(tag, Tag))
        self.add_tag(tag.tag_type, tag.value, tag.weight, usage=tag.usage,
                     classification=tag.classification,
                     context=tag.context)

    def add_tag(self, tag_type, value, weight,
                usage=None,
                classification=Classification.UNRESTRICTED,
                context=None):
        tag = {'type': tag_type, 'value': safe_str(value), 'weight': weight, 'usage': usage or self.default_usage,
               'classification': classification, 'context': context}

        for existing_tag in self.tags:
            if existing_tag['type'] == tag['type'] and \
               existing_tag['value'] == tag['value']:
                return
        self.tags.append(tag)

        if not TAG_TYPE.contains_value(tag_type):
            tb = traceback.format_stack(limit=4)
            log.warn("Invalid tag_type: %s -- %s", tag_type, tb)
        if len(value) <= 0 or len(value) >= 2048:
            tb = traceback.format_stack(limit=4)
            log.warn("invalid tag_value: %s:'%s' -- %s", tag_type, safe_str(value), tb)
        if not (isinstance(weight, int) and -1000 < weight < 1000):
            log.warn("invalid weight: %s", weight)
        if usage and not TAG_USAGE.contains_value(usage):
            log.warn("invalid tag usage: %s", usage)
        if not Classification.is_valid(classification):
            tb = traceback.format_stack(limit=4)
            log.warn("invalid classification:%s.\n%s", str(self.classification), str(tb))
        if context:
            if not Context.verify_context(tag_type, context):
                log.warn("Invalid tag_type: %s and context: %s combination" % (tag_type, context))

    # for legacy use only
    def add_result(self, section, on_top=False):
        self.add_section(section)

    def add_section(self, section, on_top=False):
        if on_top:
            self.sections.insert(0, section)
        else:
            self.sections.append(section)
        self.classification = Classification.max_classification(section.classification, self.classification)
        self.score += section.score

    def report_heuristic(self, heur):
        if isinstance(heur, Heuristic):
            self.add_tag(TAG_TYPE.HEURISTIC, heur.id, SCORE.NULL,
                         usage=TAG_USAGE.IDENTIFICATION, classification=heur.classification)
        else:
            log.warning("Report heuristics should now pass Heuristics objects not dictionary. "
                        "Update your service code.")
            self.add_tag(TAG_TYPE.HEURISTIC, heur['id'], SCORE.NULL,
                         usage=TAG_USAGE.IDENTIFICATION, classification=heur['classification'])

    def finalize(self):
        self.score = 0
        self.classification = Classification.UNRESTRICTED
        for section in self.sections:
            section.parent = self
            if section.finalize():
                self.classification = Classification.max_classification(section.classification, self.classification)
        for tag in self.tags:
            self.tags_score += tag['weight']
            self.classification = Classification.max_classification(tag['classification'], self.classification)
        if self.order_by_score:
            self.sections.sort(cmp=lambda x, y: cmp(x['score'], y['score']), reverse=True)
        self.pop('order_by_score')
        return self

    def order_results_by_score(self):
        self.order_by_score = True
        
    def set_truncated(self):
        if not self.truncated:
            self.truncated = True
            self.add_tag(TAG_TYPE.FILE_SUMMARY, 'Truncated Result', TAG_WEIGHT.NULL)

    def __getattribute__(self, attr):
        if attr in self:
            return self[attr]
        else:
            return dict.__getattribute__(self, attr)

    def __setattr__(self, attr, val):
        if attr not in self.allowed:
            raise Exception('This field is not valid in a Result: %s' % attr)
        self[attr] = val
