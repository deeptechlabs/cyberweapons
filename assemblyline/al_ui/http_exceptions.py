class NotFoundException(Exception):
    pass


class AccessDeniedException(Exception):
    pass


class InvalidDataException(Exception):
    pass


class QuotaExceededException(Exception):
    pass


class AuthenticationException(Exception):
    pass
