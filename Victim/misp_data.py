from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert
from pathlib import Path

"""
    Short description of the created event
"""
distribution = None  # Optional, defaults to MISP.default_event_distribution in MISP config
threat_level_id = 1  # Optional, defaults to MISP.default_event_threat_level in MISP config
analysis = None  # Optional, defaults to 0 (initial analysis)
info = "This event is created with PyMisp for tests"

"""
    This class is used to manage all MISP information
           - creates an event
           - creates attributes using files
           - add tag to event
           - load attributes on the MISP machine
"""


class MispEvent():

    pymisp = None

    def __init__(self):
        self.pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

    def create_new_event(self):
        """
            Function used to create new event; the event will be used to store the data added by attacker
        """
        event = MISPEvent()
        event.distribution = distribution
        event.threat_level_id = threat_level_id
        event.analysis = analysis
        event.info = info

        event = self.pymisp.add_event(event, pythonify=True)

        if event.id:
            result = self.pymisp.search(eventid=event.id)
            for event in result:
                uuid = event['Event']['uuid']

        self.pymisp.tag(uuid, 574)
        return event

    def create_attributes(self, files, type, event_id):
        """
            Function used to create attributes for added files
        """
        attributes = []
        for f in files:
            a = MISPAttribute()
            a.type = type
            a.value = f.name
            a.data = f
            a.distribution = distribution
            if type == 'malware-sample':
                a.expand = 'binary'
            attributes.append(a)

        for a in attributes:
            self.pymisp.add_attribute(event_id, a)

    def upload_file(self, data, is_malware=False, event_id=1436):
        """
            Function that marks the type of files added
        """
        files = []
        p = Path(data)
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = [f for f in p.glob('**/*') if f.is_file()]
        else:
            print('invalid upload path (must be file or dir)')
            exit(0)

        if is_malware:
            type = 'malware-sample'
        else:
            type = 'attachment'

        self.create_attributes(files, type, event_id)

    def load_data_on_misp(self, data, misp_event):
        """
            Function used to upload file as an attribute for a specific event
            This file can be interpreted as: 1. PDF    2. malware    3. string
        """
        p = Path(data)
        if p.is_file() and data.endswith('.pdf'):
            self.upload_file(data=data, is_malware=False, event_id=misp_event['Event']['id'])
        elif p.is_file() and data.endswith('.zip'):
            self.upload_file(data=data, is_malware=True, event_id=misp_event['Event']['id'])
        else:
            result = self.pymisp.freetext(misp_event['Event']['id'], data)


