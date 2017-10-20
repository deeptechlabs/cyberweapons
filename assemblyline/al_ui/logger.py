from flask import request
from al_ui.config import BUILD_NO


def get_traceback_info(tb):
    tb_list = []
    tb_id = 0
    last_ui = None
    while tb is not None:
        f = tb.tb_frame
        line_no = tb.tb_lineno
        tb_list.append((f, line_no))
        tb = tb.tb_next
        if "/ui/" in f.f_code.co_filename:
            last_ui = tb_id
        tb_id += 1

    if last_ui is not None:
        tb_frame, line = tb_list[last_ui]
        user = tb_frame.f_locals.get('kwargs', {}).get('user', None)

        if not user:
            temp = tb_frame.f_locals.get('_', {})
            if isinstance(temp, dict):
                user = temp.get('user', None)

        if not user:
            user = tb_frame.f_locals.get('user', None)

        if not user:
            user = tb_frame.f_locals.get('impersonator', None)

        if user:
            return user, tb_frame.f_code.co_filename, tb_frame.f_code.co_name, line

        return None

    return None


def dumb_log(log, msg, is_exception=False):
    args = request.query_string
    if args:
        args = "?%s" % args

    message = "%s - %s%s" % (msg, request.path, args)
    if is_exception:
        log.exception(message)
    else:
        log.warning(message)


def log_with_traceback(log, traceback, msg, is_exception=False):
    tb_info = get_traceback_info(traceback)
    if tb_info:
        tb_user, tb_file, tb_function, tb_line_no = tb_info
        args = request.query_string
        if args:
            args = "?%s" % args

        # noinspection PyBroadException
        try:
            message = "%s [%s] :: %s - %s:%s:%s[%s] (%s%s)" % (tb_user['uname'],
                                                               tb_user['classification'],
                                                               msg,
                                                               tb_file, tb_function,
                                                               tb_line_no, BUILD_NO, request.path, args)
            if is_exception:
                log.exception(message)
            else:
                log.warning(message)
        except:
            dumb_log(log, msg, is_exception=is_exception)
    else:
        dumb_log(log, msg, is_exception=is_exception)
