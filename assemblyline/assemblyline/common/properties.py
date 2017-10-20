# Properties and classmethods don't work well together. To define a class
# property we need to create a new property decorator, classproperty, and
# override the __get__ method which would have looked something like this:
#     def __get__(self, obj, objtype=None):
#         if obj is None:
#             return self
#         if self.fget is None:
#             raise AttributeError, "unreadable attribute"
#         return self.fget(obj)
#  
# We apply the classproperty decorator to a classmethod. Which looks like
# this:
#
# @classproperty
# @classmethod
# def ...


# noinspection PyPep8Naming,PyMethodOverriding
class classproperty(property):
    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()  # pylint:disable=E1101
