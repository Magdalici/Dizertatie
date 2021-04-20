#!/usr/bin/env python
import pika
import sys

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

channel.exchange_declare(exchange='direct_ioc', exchange_type='direct')

severity = sys.argv[1] if len(sys.argv) > 1 else 'misp intel'
message = ' '.join(sys.argv[2:]) or 'comment'
channel.basic_publish(
    exchange='direct_ioc', routing_key=severity, body=message)
print(" [x] Sent %r:%r" % (severity, message))
connection.close()
