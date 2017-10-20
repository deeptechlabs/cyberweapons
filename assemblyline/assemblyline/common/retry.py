from inspect import getmembers, ismethod
from sys import exc_info
from time import sleep


# noinspection PyPep8Naming
class retry(object):
    """
    This class can be used to perform an automatic retry with (a truncated
    binary exponential backoff) delay of a function/method that throws an
    exception.
    """

    def __init__(self, exceptions, retries=4, initial=1, handle=None):
        self.exceptions = exceptions
        self.handle = handle
        self.initial = initial
        self.power = 2
        self.retries = retries

    def __call__(self, original):
        """We can use an instance of this class as a decorator."""

        def wrapper(*args, **kwargs):
            return self.execute(original, *args, **kwargs)

        # Make this a well-behaved decorator.
        wrapper.__name__ = original.__name__
        wrapper.__doc__ = original.__doc__
        wrapper.__dict__.update(original.__dict__)

        return wrapper

    def execute(self, func, *args, **kwargs):
        """We can create an instance and invoke execute directly."""
        delay = self.initial
        count = 1

        while True:
            try:
                return func(*args, **kwargs)
            except self.exceptions:
                if self.retries:
                    if count > self.retries:
                        if self.handle:
                            self.handle(exc_info())
                        else:
                            raise
                    else:
                        count += 1

                sleep(delay)

                if self.retries and count <= self.retries:
                    delay *= self.power

    @staticmethod
    def forever(e):
        pass


# noinspection PyPep8Naming
class retryall(object):
    """
    This class can be used as a decorator to override the type of exceptions returned by every method of a class
    """

    def __init__(self, exceptions, retries=4, initial=1, handle=False):
        self.retry = retry(exceptions, retries, initial, handle)

    def __call__(self, cls):
        """We can use an instance of this class as a decorator."""
        for method in getmembers(cls, predicate=ismethod):
            setattr(cls, method[0], self.retry(method[1]))

        return cls
