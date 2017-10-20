import array
import io

from math import ceil, log

frequency = None


def calculate_entropy(contents):
    """ this function calculates the entropy of the file
        It is given by the formula:
            E = -SUM[v in 0..255](p(v) * ln(p(v)))
    """

    data_length = len(contents)

    if data_length == 0:
        return 0

    count = array.array('L', [0] * 256)

    # keep a count of all the bytes
    for byte in contents:
        count[ord(byte)] += 1

    entropy = float(0)

    for value in count:
        if value:
            prob = (float(value) / data_length)
            entropy += (prob * log(prob, 2))
    entropy *= -1

    return entropy


def calculate_partition_entropy(fin, num_partitions=50):
    """Calculate the entropy of a file and its partitions."""

    # Split input into num_parititions and calculate
    # parition entropy.
    fin.seek(0, io.SEEK_END)
    size = fin.tell()
    fin.seek(0)
    partition_size = int(ceil(size / float(num_partitions)))

    # Also calculate full file entropy using buffered calculator.
    p_entropies = []
    fullentropy = BufferedCalculator()
    for _ in range(num_partitions):
        partition = fin.read(partition_size)
        p_entropies.append(calculate_entropy(partition))
        fullentropy.update(partition)
    return fullentropy.entropy(), p_entropies


# noinspection PyUnresolvedReferences
class BufferedCalculator(object):
    def __init__(self):
        global frequency
        import pyximport
        pyximport.install()  # pylint: disable=C0321
        from assemblyline.common import frequency  # pylint: disable=E0611

        self.c = {}
        self.l = 0

    def entropy(self):
        if self.l == 0:
            return 0.0

        length = float(self.l)

        entropy = 0.0
        for v in self.c.itervalues():
            prob = float(v) / length
            entropy += prob * log(prob, 2)

        entropy *= -1

        # Make sure we don't return -0.0.
        if not entropy:
            entropy = 0.0

        return entropy

    def update(self, data, length=0):
        if not length:
            length = len(data)

        self.l += length
        self.c = frequency.counts(data, length, self.c)
