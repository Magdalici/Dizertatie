import time
from queue import Queue
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPObject
from keys import misp_url, misp_key, misp_verifycert

PATHTOBEOBSERVED = '.'

#add data needed to create new event
distribution = None  # Optional, defaults to MISP.default_event_distribution in MISP config
threat_level_id = 1  # Optional, defaults to MISP.default_event_threat_level in MISP config
analysis = None  # Optional, defaults to 0 (initial analysis)
info = "This event is created with PyMisp for tests"

# create misp instance
pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

def create_new_event():
    # create MISPEvent object
    event = MISPEvent()
    event.distribution = distribution
    event.threat_level_id = threat_level_id
    event.analysis = analysis
    event.info = info
    event = pymisp.add_event(event, pythonify=True)
    return event

def on_created(event):
     print(f"{event.src_path} has been created!")

def on_deleted(event):
    print(f"Someone deleted {event.src_path}!")

def on_modified(event):
    print(f"{event.src_path} has been modified")

def on_moved(event):
    print(f"Someone moved {event.src_path} to {event.dest_path}")

def get_data_from_queue(queue, misp_event):
    while True:
        if not queue.empty():
            event = queue.get()
            print("Evenimentul")
            print(event)
            data = event.src_path.replace('/','')
            result = pymisp.freetext(misp_event.id, data)
        else:
            time.sleep(1)

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

if __name__ == "__main__":

    patterns = "*"
    ignore_patterns = ["*.swp"]
    ignore_directories = False
    case_sensitive = True
    '''my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
    
    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved'''

    my_queue = Queue()
    misp_event = create_new_event()

    # setup worker thread to add data to misp
    worker = Thread(target = get_data_from_queue, args=(my_queue, misp_event,))
    worker.setDaemon(True)
    worker.start()

    my_event_handler = MispLoaderWatchdog(my_queue,
                               patterns,
                               ignore_patterns,
                               ignore_directories,
                               case_sensitive)
    path = PATHTOBEOBSERVED
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
