import socket
import subprocess
import threading
import time


class TimeoutException(Exception):
    pass


def timeout(func, args=(), kwargs=None, timeout_duration=10, default=None):
    class InterruptableThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = default
            self.error = None
            self.cancel = False

        def run(self):
            while True:
                try:
                    self.result = func(*args, **kwargs)
                    break
                except socket.error, e:
                    if e.errno == 111 and not self.cancel:
                        time.sleep(0.1)
                    else:
                        self.error = e
                        break
                except Exception, e:
                    self.error = e
                    break

    if kwargs is None:
        kwargs = {}

    it = InterruptableThread()
    it.start()
    it.join(timeout_duration)
    if it.isAlive():
        it.cancel = True
        raise TimeoutException()
    else:
        if it.error:
            raise BaseException(it.error)
        return it.result


# noinspection PyBroadException
class SubprocessTimer(object):
    def __init__(self, timeout_value, raise_on_timeout=True):
        self.timeout = timeout_value
        self.timed_out = False
        self.stime = 0
        self.proc = None
        self.stop = False
        self.raise_on_timeout = raise_on_timeout
        self.timeout_t = self._init_thread()

    def __enter__(self):
        self.timeout_t.start()
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        if self.timed_out and self.raise_on_timeout:
            raise TimeoutException("%s seconds timeout reached" % self.timeout)

    def _init_thread(self):
        t = threading.Thread(target=self._check_timeout,
                             name="PROCESS_TIMEOUT_THREAD_%s_SEC" % str(self.timeout))
        t.daemon = True
        return t

    def _check_timeout(self):
        while True:
            if self.stop:
                break

            if self.proc is not None:
                if time.time() - self.stime > self.timeout:
                    self.timed_out = True
                    try:
                        self.proc.kill()
                    except:
                        pass
                    self.proc = None
                    self.stime = 0
            time.sleep(0.1)

    def close(self):
        self.stop = True

    def has_timed_out(self):
        return self.timed_out

    def run(self, running_process):
        if self.timeout_t and not self.timeout_t.isAlive():
            self.timeout_t = self._init_thread()
            self.timeout_t.start()

        self.stop = False
        self.timed_out = False
        self.stime = time.time()
        self.proc = running_process

        return running_process


if __name__ == "__main__":
    def run_sp_timer(timer, shell_func):
        print "\n-->> Executing command: %s" % shell_func
        stime = time.time()
        proc = timer.run(subprocess.Popen(shell_func, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE))

        proc.wait()
        ret_val = proc.poll()

        if timer.has_timed_out():
            print "Process timeout!"
        else:
            print "Execution complete!"

        etime = time.time()
        print "Execution time: %s seconds\nReturn value: %s" % (str(etime - stime), str(ret_val))

        timer.close()

    ########################################################
    # In the following exemples, we initialize a timer and and use it multiple times
    ST = SubprocessTimer(3)
    print "\nGlobal timer kills processes running more than 3 seconds..."
    run_sp_timer(ST, 'sleep 5')
    run_sp_timer(ST, 'sleep 1')

    ########################################################
    # In the following exemple, we use a timer wrapped into a 'with' statement
    print "\n\n'With statement' timer kills processes running more than 2 seconds..."
    print "\n-->> Executing commandL: \"sleep 4\""
    stime = etime = time.time()
    ret_val = None
    try:
        with SubprocessTimer(2) as new_ST:
            proc = new_ST.run(subprocess.Popen(["sleep", "4"], stderr=subprocess.PIPE, stdout=subprocess.PIPE))
            proc.wait()
            ret_val = proc.poll()
            etime = time.time()

        print "Execution complete!"
    except TimeoutException:
        print "Process timeout!"
    finally:
        print "Execution time: %s seconds\nReturn value: %s" % (str(etime - stime), str(ret_val))
