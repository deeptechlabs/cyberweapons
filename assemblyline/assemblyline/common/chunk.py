def chunk(l, n):
    """ Yield n-sized chunks from list.
        e.g. chunk([1,2,3,4,5,6,7], 2) = [ [1,2], [3,4], [5,6], [7,] ]
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def chunked_list(l, n):
    return [x for x in chunk(l, n)]
