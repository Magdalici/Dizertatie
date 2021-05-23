from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPAttribute, MISPObject, InvalidMISPObject
from keys import misp_url, misp_key, misp_verifycert
from pathlib import Path
import os, math, zipfile
from io import BytesIO
from collections import Counter
from hashlib import md5, sha1, sha256, sha512

try:
    import magic  # type: ignore
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

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
           - creates attributes (objects) using files
           - add tag to event
           - load attributes on the MISP machine
"""


class MispEvent():
    pymisp = None
    event = None

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

    def create_attributes(self, files, type):
        """
            Function used to create attributes for added files
        """
        print("A ajuns prin crearea de un atribut SIMPLU")
        for f in files:
            a = MISPAttribute()
            a.type = type
            a.value = f.name
            a.data = f
            a.distribution = distribution
            if type == 'malware-sample':
                a.expand = 'binary'
            self.pymisp.add_attribute(self.event.id, a)



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
            Function used to create objects them for files and relation objects
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
            misp_object.add_attribute('malware-sample', value=filename, data=pseudofile)

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
        p = Path(data)
        if p.is_file():
            files = [p]
        elif p.is_dir():
            files = [f for f in p.glob('**/*') if f.is_file()]
        else:
            print('invalid upload path (must be file or dir)')
            exit(0)

        """
            zip file is treated as a malware - one attribute ; rest of files are treated as object
        """
        for f in files:
            print("Este  o arhiva? " + os.path.basename(f))
            print(zipfile.is_zipfile(os.path.basename(f)))
            if str(f).endswith('.zip'):
                self.create_attributes(files, type="malware-sample")
            else:
                self.create_objects(f)


    def load_data_on_misp(self, data):
        """
            Function used to upload file as an attribute for a specific event
            This file can be interpreted as: 1. zip file managed as malware   2. document    3. string
        """
        filepath = Path(data)

        if filepath.is_file():
            self.upload_file(data=data)
        else:
            filename = os.path.basename(data)
            self.pymisp.freetext(self.event.id, filename)
