#!/usr/bin/env python
import pika
import sys

from pymisp import ExpandedPyMISP, PyMISP, MISPEvent, MISPObject
from keys import misp_url, misp_key, misp_verifycert

#add data needed to create new event
distribution = None  # Optional, defaults to MISP.default_event_distribution in MISP config
threat_level_id = 1  # Optional, defaults to MISP.default_event_threat_level in MISP config
analysis = None  # Optional, defaults to 0 (initial analysis)
info = "This event is created with PyMisp for tests"

# create misp instance
pymisp = PyMISP(misp_url, misp_key, misp_verifycert)

def createNewEvent(attribute):
    # create MISPEvent object
    event = MISPEvent()
    event.distribution = distribution
    event.threat_level_id = threat_level_id
    event.analysis = analysis
    event.info = info
    event = pymisp.add_event(event, pythonify=True)

    result = pymisp.freetext(event.id, attribute)

   ''' mispObject = MISPObject('ans')
    mispObject.add_attribute('asn', type='AS', value=attribute)
    
    event.add_object(**mispObject)'''
    print("\tThis is a NEW EVENT: \n")
    print(event)

def addNewObject(attribute):
    mispObject = MISPObject('ans')
    mispObject.add_attribute(**attribute)
    
#PIKA connection
connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

#declare the type of exchange used to receive data from producer
channel.exchange_declare(exchange='direct_ioc', exchange_type='direct')

#declare the queue used to link the exchange to it
result = channel.queue_declare(queue='', exclusive=True)
queue_name = result.method.queue

severities = sys.argv[1:]
if not severities:
    sys.stderr.write("Usage: %s [md5] [.exe] [ssdeed]\n" % sys.argv[0])
    sys.exit(1)

#manage routing process according to the type of severity
for severity in severities:
    channel.queue_bind(
        exchange='direct_ioc', queue=queue_name, routing_key=severity)

#print(' [*] Waiting for logs. To exit press CTRL+C')

#define the callback used to manage the content from queue
def callback(ch, method, properties, body):
    body_string = body.decode("utf-8") 
    print("%s" % (body_string)) 
   
    createNewEvent(body_string)
    #result = pymisp.freetext(1424, body_string)

channel.basic_consume(
    queue=queue_name, on_message_callback=callback, auto_ack=True)

channel.start_consuming()
