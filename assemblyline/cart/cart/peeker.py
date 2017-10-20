import sys

if sys.version_info[0] == 2:
    import cStringIO as io
else:
    import io
import os


class Peeker(object):
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.buf = io.StringIO()

    def _append_to_buf(self, contents):
        oldpos = self.buf.tell()
        self.buf.seek(0, os.SEEK_END)
        self.buf.write(contents)
        self.buf.seek(oldpos)

    def peek(self, size):
        contents = self.fileobj.read(size)
        self._append_to_buf(contents)
        return contents

    def read(self, size=None):
        if size is None:
            return self.buf.read() + self.fileobj.read()
        contents = self.buf.read(size)
        if len(contents) < size:
            contents += self.fileobj.read(size - len(contents))
        return contents

    def readline(self):
        line = self.buf.readline()
        if not line.endswith('\n'):
            line += self.fileobj.readline()
        return line
