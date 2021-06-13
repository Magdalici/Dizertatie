import re
import time
import os
import subprocess
from queue import Queue
from subprocess import TimeoutExpired
from threading import Thread
from misp_data import MispEvent
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

""" Use . to monitor the current directory """
observed_path = '/home/magda/Documents/Master/Dizertatie/Attacker_env'

"""
    This class inherits the PatternMatchingEventHandler to match the given patterns with the identified files
    The watchdog will be triggered if a file is added
    Once triggered,the watchdog put the event in queue in order to be picked up by the worker thread
"""


class MispLoaderWatchdog(PatternMatchingEventHandler):

    def __init__(self, queue, patterns, ign_patterns, ign_dir, case_sensitive):
        PatternMatchingEventHandler.__init__(self,
                                             patterns=patterns,
                                             ignore_patterns=ign_patterns,
                                             ignore_directories=ign_dir,
                                             case_sensitive=case_sensitive)
        self.queue = queue

    def add(self, event):
        self.queue.put(event)

    def on_created(self, event):
        self.add(event)


def on_deleted(event):
    print(f"Someone deleted {event.src_path}!")


def on_modified(event):
    print(f"{event.src_path} has been modified")


def on_moved(event):
    print(f"Someone moved {event.src_path} to {event.dest_path}")


def find_ip_address():
    """
        Function used to find ip address of the attacker
        declaring the regex pattern for IP addresses
    """
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    command = ["lsof", "-i"]
    lsof = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        line = lsof.stdout.readline()
        if not line:
            break
        if 'pygame' in str(line):
            return pattern.search(str(line))[0]


def get_data_from_queue(queue, pymisp):
    """
        Function used to extract data from the queue and upload it to MISP
    """
    while True:
        if not queue.empty():
            event = queue.get()
            data = event.src_path.replace('./', '')
            print(queue)
            pymisp.load_data_on_misp(data)
        else:
            time.sleep(1)


def main():
    """
        This function - setup the needed patterns (ignore swap files)
                      - setup worker thread to add data to MISP
                      - creates a watchdog that will monitor the directory where the script is located
    """
    patterns = "*"
    ignore_patterns = ["*.swp"]
    ignore_directories = True # want to be notified just for regular files
    case_sensitive = True

    my_queue = Queue()
    pymisp = MispEvent()

    ip_addr = find_ip_address()
    if ip_addr:
        #ip_addr = "185.130.104.182"
        pymisp.load_data_on_misp(ip_addr)

    worker = Thread(target=get_data_from_queue, args=(my_queue, pymisp,))
    worker.setDaemon(True)
    worker.start()

    my_event_handler = MispLoaderWatchdog(my_queue,
                                          patterns,
                                          ignore_patterns,
                                          ignore_directories,
                                          case_sensitive)
    path = observed_path
    go_recursively = True

    my_observer = Observer()

    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    my_observer.start()
    try:
        while True:
            time.sleep(0.3)
    except KeyboardInterrupt:
        my_observer.stop()
    my_observer.join()


if __name__ == "__main__":
    main()