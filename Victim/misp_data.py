import re
import subprocess

from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPAttribute, MISPObject, InvalidMISPObject
from keys import misp_url, misp_key, misp_verifycert
from pathlib import Path
import os, math
from io import BytesIO
from collections import Counter
from hashlib import md5, sha1, sha256, sha512
import imghdr
import statistics

try:
    import magic  # type: ignore

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

"""
    Short description of the created event
"""
distribution = None  # Optional, defaults to MISP.default_event_distribution in MISP config
threat_level_id = 4  # No risk
analysis = None  # default to 0- initial analysis
info = "This event is related to a suspicious activity"

"""
    This class is used to manage all MISP information
           - creates an event
           - creates attributes (objects) using files
           - add tag to event
           - load attributes on the MISP machine
"""


class MispEvent:

    def __init__(self):
        self.pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
        self.event = self.create_new_event()

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

        """tlp:white TAG"""
        self.pymisp.tag(event.uuid, 3)

        """ecsirt:intrusions='backdoor' TAG"""
        self.pymisp.tag(event.uuid, 574)

        return event

    def create_attributes(self, files, type, tags):
        """
            Function used to create attributes for added files
        """

        for f in files:
            a = MISPAttribute()
            a.type = type
            a.value = f.name
            a.data = f
            a.distribution = distribution

            attr = self.pymisp.add_attribute(self.event.id, a)

            if type == 'malware-sample':
                self.pymisp.tag(attr['Attribute']['uuid'], 154)

            self.pymisp.update_event(self.event)

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

    def create_objects(self, filepath):
        """
            Function used to create objects for files and relation objects
        """
        if filepath:
            with open(filepath, 'rb') as f:
                pseudofile = BytesIO(f.read())
        else:
            raise InvalidMISPObject('File buffer (BytesIO) or a path is required.')

        data = pseudofile.getvalue()
        filename = os.path.basename(filepath)

        misp_object = self.event.add_object(name='file',
                                            comment='This object contains the name of the detected file, ' + filename,
                                            standalone=False)

        misp_object.add_attribute('filename', value=filename)
        size = misp_object.add_attribute('size-in-bytes', value=len(data))

        self.pymisp.add_object(self.event.id, misp_object)
        file_object_id = misp_object.uuid

        if int(size.value) > 0:
            misp_object = self.event.add_object(name='file',
                                                comment='This object contains additional information for ' + filename,
                                                standalone=False)

            misp_object.add_attribute('entropy', value=self.entropy_H(data))
            misp_object.add_attribute('md5', value=md5(data).hexdigest())
            misp_object.add_attribute('sha1', value=sha1(data).hexdigest())
            misp_object.add_attribute('sha256', value=sha256(data).hexdigest())
            misp_object.add_attribute('sha512', value=sha512(data).hexdigest())
            # here was 'malware-sample' but for doc files didn't upload it as malware-sample
            misp_object.add_attribute('attachment', value=filename, data=pseudofile)

            if HAS_MAGIC:
                misp_object.add_attribute('mimetype', value=magic.from_buffer(data, mime=True))

            self.pymisp.add_object(self.event.id, misp_object)

            misp_object.add_reference(referenced_uuid=file_object_id, relationship_type='related-to',
                                      comment='Relation between an attribute and its characteristics ')

            self.pymisp.update_event(self.event)

    def upload_file(self, data):
        """
            Function that marks the type of added files
        """
        files = []
        extensions = ["jpeg", "jpg", "png"]

        p = Path(data)
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = [f for f in p.glob('**/*') if f.is_file()]
        else:
            print('invalid upload path (must be file or dir)')
            exit(0)

        """
            zip file is treated as a malware - one attribute; images as attachment; 
            rest of files are treated as object
        """
        for f in files:
            f_extension = imghdr.what(f)
            print(f_extension)
            if f_extension in extensions:
                self.create_attributes(files, type="attachment", tags='')
            elif str(f).endswith('.zip'):
                self.create_attributes(files, type="malware-sample",
                                       tags='malware_classification:malware-category="Trojan"')
            else:
                self.create_objects(f)

        self.update_thread_level_id()

    def update_thread_level_id(self):
        """
           Function used to calculate the average thread level id based on the threat level from related events
        """
        thread_level_id_list = []
        event_info_dict = self.pymisp.get_event(self.event.id)
        data = event_info_dict['Event']
        for event in data['RelatedEvent']:
            if event:
                thread_level_id_list.append(int(event['Event']['threat_level_id']))
        if thread_level_id_list:
            new_threat_level_id = math.trunc(statistics.mean(thread_level_id_list))
            self.event.threat_level_id = new_threat_level_id

            print("Thread_level_id evenimentelor corelate sunt: ")
            print(thread_level_id_list)
            print(math.trunc(statistics.mean(thread_level_id_list)))

            self.pymisp.update_event(self.event)

    def load_data_on_misp(self, data):
        """
            Function used to upload file as an attribute for a specific event
        """
        filepath = Path(data)

        if filepath.is_file():
            self.upload_file(data=data)
        else:
            self.pymisp.freetext(self.event.id, data)

