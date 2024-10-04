#
# wekassh - a simpler interface to paramiko for doing ssh to other servers
#
import getpass
import os
from _socket import gaierror
from logging import getLogger

import fabric
from fabric import OpenSSHAuthStrategy

#import paramiko
#from scp import SCPClient

from wekapyutils.sthreads import threaded, default_threader

log = getLogger(__name__)


class AuthenticationException(Exception):
    pass

    def __str__(self):
        return "Authentication Failed"


class CommandOutput(object):
    def __init__(self, status, stdout, stderr, exception=None):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.exception = exception

    def __str__(self):
        return f"status={self.status}, stdout={self.stdout}, stderr={self.stderr}, exception={self.exception}"


class RemoteServer():
    def __init__(self, hostname):
        self.kwargs = dict()
        self.output = None
        #self.connection = fabric.Connection(hostname)
        self.connection = None
        self._hostname = hostname
        self.exc = None
        self.user = None
        self.password = None
        self.connected = False

        self.config = fabric.Config(overrides={'authentication': {'strategy_class': OpenSSHAuthStrategy}})
        #c = Connection('hostname', config=config)

    def ask_for_credentials(self):
        print(f"Enter credentials for server {self._hostname}:")
        print(f"Username({self.user}): ", end='')
        user = input()
        if len(user) != 0:
            self.user = user
        self.password = getpass.getpass()
        print()
        # return (user, password)

    def connect(self, forward_agent=False):
        failures = 0
        #self.kwargs = {"forward_agent": forward_agent}
        while True:
            if self.password is not None and len(self.password) > 0:
                self.config = fabric.Config()   # reset the config to clear the auth strategy
                self.kwargs["password"] = self.password
            try:
                #self.connection = fabric.Connection(self._hostname, forward_agent=forward_agent, connect_kwargs=self.kwargs)
                self.connection = fabric.Connection(host=self._hostname,
                                                    user=self.user,
                                                    connect_timeout=10,
                                                    connect_kwargs=self.kwargs,
                                                    config=self.config)
                if 'password' in self.kwargs:
                    # if we're using a password, we don't want to use a keyfile - fabric sometimes sticks one in there
                    if 'key_filename' in self.connection.connect_kwargs:
                        del self.connection.connect_kwargs['key_filename']
                self.connection.open()
                self.connected = True
                self.user = self.connection.user
                if getattr(self.connection, 'password', None) is not None:
                    self.password = self.connection.password
                return
            except gaierror as exc:
                log.error(f"Error connecting to {self._hostname}: hostname not found")
                self.connected = False
                return
            except Exception as exc:
                log.error(f"Error connecting to {self._hostname}: {exc}")
                failures += 1
                if getattr(self, "___interactive", True) and failures <= 3:
                    self.config = fabric.Config()
                    log.info(f"trying to connect to {self._hostname} interactively")
                    self.ask_for_credentials()
                    self.kwargs = {"password": self.password, "key_filename": []}
                    #del self.connection
                else:
                    log.error(f"Failure to log into {self._hostname}")
        return

    def close(self):
        self.end_unending()  # kills the fio --server process
        self.connection.close()
        #super().close()
        
    def get_transport(self):
        return self.connection.transport

    def scp(self, source, dest):
        log.info(f"copying {source} to {self._hostname}")
        self.connection.put(source, dest)

    def run(self, cmd):
        """

        :param cmd:
        :type cmd:
        :return:returns a CommandOutput object with the results of the command
                         and also stores it in self.output
        :rtype:
        """
        if self.connection is None:
            log.error(f'Cannot run command - not connected to host {self._hostname}')
            return
        try:
            result = self.connection.run(cmd, hide=True)
            #self.output = CommandOutput(result.return_code, result.stdout, result.stderr, exc)
        except gaierror as exc:
            log.error(f"Error connecting to {self._hostname}: hostname not found")
            self.output = CommandOutput(127, "hostname not found", "", exc)
        except Exception as exc:
            log.debug(f"run (Exception): '{cmd[:100]}', exception='{exc}'")
            result = exc.result
            self.output = CommandOutput(result.return_code, result.stdout, result.stderr, exc)
        else:
            self.output = CommandOutput(result.return_code, result.stdout, result.stderr)
        return self.output

    def _linux_to_dict(self, separator):
        output = dict()
        if self.output['status'] != 0:
            log.debug(f"last output = {self.output}")
            raise Exception
        lines = self.output['response'].split('\n')
        for line in lines:
            if len(line) != 0:
                line_split = line.split(separator)
                if len(line_split) == 2:
                    output[line_split[0].strip()] = line_split[1].strip()
        return output

    def _count_cpus(self):
        """ count up the cpus; 0,1-4,7,etc """
        num_cores = 0
        cpulist = self.output.stdout.strip(' \n').split(',')
        for item in cpulist:
            if '-' in item:
                parts = item.split('-')
                num_cores += int(parts[1]) - int(parts[0]) + 1
            else:
                num_cores += 1
        return num_cores

    def gather_facts(self, weka):
        """ build a dict from the output of lscpu """
        self.cpu_info = dict()
        self.run("lscpu")

        # cpuinfo = self.last_output['response']
        self.cpu_info = self._linux_to_dict(':')

        self.run("cat /etc/os-release")
        self.os_info = self._linux_to_dict('=')

        self.run("cat /sys/fs/cgroup/cpuset/system/cpuset.cpus")
        self.usable_cpus = self._count_cpus()

        if weka:
            self.run('mount | grep wekafs')
            log.debug(f"{self.output}")
            if len(self.output['response']) == 0:
                log.debug(f"{self._hostname} does not have a weka filesystem mounted.")
                self.weka_mounted = False
            else:
                self.weka_mounted = True

    def file_exists(self, path):
        """ see if a file exists on another server """
        log.debug(f"checking for presence of file {path} on server {self._hostname}")
        self.run(f"if [ -f '{path}' ]; then echo 'True'; else echo 'False'; fi")
        strippedstr = self.output['response'].strip(' \n')
        log.debug(f"server responded with {strippedstr}")
        if strippedstr == "True":
            return True
        else:
            return False

    def last_response(self):
        return self.output

    def __str__(self):
        return self._hostname

    def run_unending(self, command):
        """ run a command that never ends - needs to be terminated by ^c or something """
        #transport = self.get_transport()
        transport = self.connection.client.get_transport()
        self.unending_session = transport.open_session()
        self.unending_session.setblocking(0)  # Set to non-blocking mode
        self.unending_session.get_pty()
        self.unending_session.invoke_shell()
        self.unending_session.command = command

        # Send command
        log.debug(f"starting daemon {self.unending_session.command}")
        self.unending_session.send(command + '\n')

    def end_unending(self):
        log.debug(f"terminating daemon {self.unending_session.command}")
        self.unending_session.send(chr(3))  # send a ^C
        self.unending_session.close()

    def invoke_shell(self):
        """ invoke a shell on the remote server. Use self.shell.close() to terminate it """
        self.shell = self.connection.client.invoke_shell()
        return self.shell


@threaded
def threaded_method(instance, method, *args, **kwargs):
    """ makes ANY method of ANY class threaded """
    method(instance, *args, **kwargs)


def parallel(obj_list, method, *args, **kwargs):
    for instance in obj_list:
        instance.___interactive = False  # mark them all as parallel jobs
        threaded_method(instance, method, *args, **kwargs)
    default_threader.run()  # wait for them
    for instance in obj_list:
        instance.___interactive = True  # undo that when done


def pdsh(servers, command):
    parallel(servers, RemoteServer.run, command)


def pscp(servers, source, dest):
    log.debug(f"setting up parallel copy to {servers}")
    parallel(servers, RemoteServer.scp, source, dest)

if __name__ == '__main__':
    import sys, time, logging
    log.setLevel("DEBUG")
    console_format = "%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(console_format))
    log.addHandler(console_handler)

    test1 = RemoteServer("172.29.7.237")
    test1.user = "root"
    test1.password = "WekaService"
    result = test1.connect()
    shell = test1.invoke_shell()
    time.sleep(0.5)
    output = shell.recv(500).strip().decode("utf-8")
    print(f"output received from shell: {output}")
    shell.close()

    sys.exit()
    # result2 = test1.run("exit")
    #print(result2)
    # print(result2.stdout)
    test1.scp("wekapyutils/wekassh.py", "/tmp/wekassh.py")
    result = test1.run("ls -l /tmp/wekassh.py")
    print(result.stdout)

    servers = [RemoteServer("wms"), RemoteServer("buckaroo"), RemoteServer("whorfin")]
    parallel(servers, RemoteServer.connect)
    parallel(servers, RemoteServer.run, "hostname")
    default_threader.run()
    print("done")
    for i in servers:
        print(i.last_response())
    pass