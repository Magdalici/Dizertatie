import os, math, re
import subprocess
from collections import Counter
from pathlib import Path

PATH_PYGAME = "/home/magda/Documents/Master/Dizertatie/Attacker_env/pygame"

"""
    This class is used to:
        - compute entropy for file's content
        - create list of files from a directory
        - identify the PID of PYGAME process based on a network connection
        - notify the user about the level of risk under root privileges
        - take some decisions about the level of risk
"""


class Helper:

    def entropy_H(self, data: bytes) -> float:
        """
            Function used to calculate the entropy of a chunk of data.
        """

        if len(data) == 0:
            return 0.0

        occurrences = Counter(bytearray(data))

        entropy = 0.0
        for x in occurrences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy

    def create_list_files(self, data):
        """
            Function used to create a list of files
        """
        p = Path(data)
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = [f for f in p.glob('**/*') if f.is_file()]
        else:
            print('invalid upload path (must be file or dir)')
            exit(0)
        return files

    def remove_exe_immutable(self, exe):
        """
            Function used to remove execution permission and make the file immutable
        """
        chmod_command = ["chmod", "-x", exe]
        subprocess.Popen(chmod_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        chattr_command = ["chattr", "+i", exe]
        subprocess.Popen(chattr_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def kill_process(self, exe):
        """
            Function used to interrupt the process PYGAME
        """
        pid = self.find_pid_pygame()
        print(pid)

        execution_permiss = os.access(exe, os.X_OK)
        if execution_permiss:
            self.remove_exe_immutable(exe)

        kill_command = ["kill", "-9", pid]
        subprocess.Popen(kill_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def kill_process_remove_file(self, exe, file):
        """
                  Function used to interrupt the process PYGAME and remove the new file added
        """
        pid = self.find_pid_pygame()
        print(pid)

        execution_permiss = os.access(exe, os.X_OK)
        if execution_permiss:
            self.remove_exe_immutable(exe)

        kill_command = ["kill", "-9", pid]
        subprocess.Popen(kill_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        remove_command = ["rm", "-rf", file]
        subprocess.Popen(remove_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def notify(self, title, message):
        """
            Function used to send desktop notifications using the notify-send program
        """
        user_id = subprocess.run(['id', '-u', os.environ['SUDO_USER']],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 check=True).stdout.decode("utf-8").replace('\n', '')

        subprocess.run(['sudo', '-u', os.environ['SUDO_USER'],
                        'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{}/bus'.format(user_id),
                        'notify-send', '-i', 'utilities-terminal', title, message],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       check=True)

    def find_pid_pygame(self):
        """
            Function used to find the pid of the PYGAME process based on network connection
        """
        command = ["lsof", "-i"]
        ps = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while True:
            line = ps.stdout.readline()
            if not line:
                break
            if 'pygame' in str(line):
                string = line.decode('UTF-8')
                remove_spaces = re.sub(' +', ' ', string)
                pid = remove_spaces.split(' ')[1]
                return pid