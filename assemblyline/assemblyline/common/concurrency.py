
import time
import threading

from datetime import datetime

from assemblyline.common.timeout import timeout, TimeoutException


class SkipException(Exception):
    pass


def execute_concurrently(execution_plan, calculate_timers=False, max_timeout=None):
    """
    This is a semi-async execution of a given set of function. All the functions will be executed at the same time
    but it will wait for all functions to finish before returning any results.

    Use this when you have multiple independent IO calls.

    :param execution_plan: a list of tuples containing:
                            function name
                            function arguments (as a tuple)
                            return value name
    :param calculate_timers: a boolean which returns _timers_ dictionary with execution time for each functions
    :param max_timeout: Maximum execution time for each function, in seconds
    :return: Return each function execution inside a dictionary based on the name given in the execution plan
    """
    def bench(p_func, p_args, p_name):
        s_time = time.time()
        if max_timeout is not None:
            try:
                output = timeout(p_func, p_args, timeout_duration=max_timeout)
            except TimeoutException:
                out["_timeout_"].append(p_name)
                raise SkipException()
        else:
            output = p_func(*p_args)
        out["_timers_"][p_name] = float("%.3f" % (time.time() - s_time))
        return output

    def exec_async(p_func, p_args, p_name):
        try:
            if calculate_timers:
                out[p_name] = bench(p_func, p_args, p_name)
            else:
                if max_timeout is not None:
                    try:
                        out[p_name] = timeout(p_func, p_args, timeout_duration=max_timeout)
                    except TimeoutException:
                        out["_timeout_"].append(p_name)
                else:
                    out[p_name] = p_func(*p_args)
        except SkipException:
            pass
        except BaseException, e:
            if "_exception_" not in out:
                out["_exception_"] = {}
            out["_exception_"][p_name] = e

    # DO NOT REMOVE!!! THIS IS MAGIC!
    # strptime Thread safe fix... yeah ...
    datetime.strptime("2000", "%Y")
    # END OF MAGIC

    threads = []
    out = {}
    if max_timeout is not None:
        out["_timeout_"] = []

    if calculate_timers:
        out["_timers_"] = {}

    for func, args, name in execution_plan:
        t = threading.Thread(target=exec_async, args=(func, args, name), name=name)
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    return out

#################################################
# UNIT TEST
if __name__ == "__main__":
    def f1(p_range):
        out = 0
        for x in xrange(p_range):
            out += x
        return out

    plan = [(f1, (20, ), "t1"),
            (f1, (30, ), "t2"),
            (f1, (15, ), "t3")]

    print execute_concurrently(plan)
