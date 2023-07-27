#!/usr/bin/env python3

import os
import pika
import sys

credentials = pika.PlainCredentials('xython', 'password')


def main():
    print("toto")
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1', port=5672, credentials=credentials))
    channel = connection.channel()

    channel.queue_declare(queue='xython-ping')

    # @@status#62503/karnov|1684156989.403184|172.16.1.22||karnov|lr|1684243389|red||red|1682515389|0||0||1684156916|linux||0|
    def callback(ch, method, properties, body):
        print(body)

    channel.basic_consume(queue='xython-ping', on_message_callback=callback, auto_ack=True)

    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()


print("start")
main()
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
