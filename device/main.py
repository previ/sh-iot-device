# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import machine
import esp32
from third_party import string
import network
import socket
import os
import utime
import ssl
from third_party import rsa
from umqtt.simple import MQTTClient
from ubinascii import b2a_base64, a2b_base64
from machine import RTC, Pin
from third_party import ota_updater
from third_party import htu21d
import ntptime
import ujson



class Device():

    def __init__(self):
        f = open('config.json')
        self.config = ujson.load(f)
        f.close()
        self.sta_if = network.WLAN(network.STA_IF)
        self.ota = ota_updater.OTAUpdater(github_repo=self.config['ota_config']['repo_url'], main_dir=self.config['ota_config']['repo_url'])
        self.jwt = None
        self.client = None
        self.led_pin = machine.Pin(self.config['device_config']['led_pin'], Pin.OUT) #built-in LED pin
        self.led_pin.value(1)
        self.sensor = htu21d.HTU21D(22,21)

    def on_message(self, topic, message):
        try:
            print((topic, message))
            message_json = ujson.loads(message.decode('utf-8'))
            if 'config' in topic:
                self.config.update(message_json)
                f = open('config.json', 'w')
                ujson.dump(self.config, f)
                f.close()
            if 'command' in topic:
                if message_json.get('cmd') == "write_file":
                    file_name = message_json.get('file_name')
                    file_body = a2b_base64(message_json.get('file_body'))
                    f = open(file_name, 'w')
                    f.close()
                if message_json.get('cmd') == "restart":
                    sys.exit()
                if message_json.get('cmd') == "reset":
                    machine.reset()
                if message_json.get('cmd') == "update":
                    self.o.download_and_install_update_if_available(None, None)                    
        except Exception as e:
            print("on_message.Exception: " + str(e))

    def is_connected(self):
        return (self.sta_if.isconnected())

    def connect_wifi(self):
        print('connecting to network...')
        self.sta_if.active(True)
        self.sta_if.connect(self.config['wifi_config']['ssid'], self.config['wifi_config']['password'])
        while not self.sta_if.isconnected():
            pass
        print('network config: {}'.format(self.sta_if.ifconfig()))

    def set_time(self):
        ntptime.settime()
        tm = utime.localtime()
        tm = tm[0:3] + (0,) + tm[3:6] + (0,)
        machine.RTC().datetime(tm)
        print('current localtime: {}'.format(utime.localtime()))
        print('current time: {}'.format(utime.time()))

    def b42_urlsafe_encode(self, payload):
        return string.translate(b2a_base64(payload)[:-1].decode('utf-8'),{ ord('+'):'-', ord('/'):'_' })

    def create_jwt(self, project_id, private_key, algorithm, token_ttl):
        print("Creating JWT...")
        private_key = rsa.PrivateKey(*private_key)

        # Epoch_offset is needed because micropython epoch is 2000-1-1 and unix is 1970-1-1. Adding 946684800 (30 years)
        epoch_offset = 946684800
        claims = {
                # The time that the token was issued at
                'iat': utime.time() + epoch_offset,
                # The time the token expires.
                'exp': utime.time() + epoch_offset + token_ttl,
                # The audience field should always be set to the GCP project id.
                'aud': project_id
        }

        #This only supports RS256 at this time.
        header = { "alg": algorithm, "typ": "JWT" }
        content = self.b42_urlsafe_encode(ujson.dumps(header).encode('utf-8'))
        content = content + '.' + self.b42_urlsafe_encode(ujson.dumps(claims).encode('utf-8'))
        signature = self.b42_urlsafe_encode(rsa.sign(content,private_key,'SHA-256'))
        return content+ '.' + signature #signed JWT

    def get_mqtt_client(self, project_id, cloud_region, registry_id, device_id, jwt):
        """Create our MQTT client. The client_id is a unique string that identifies
        this device. For Google Cloud IoT Core, it must be in the format below."""
        client_id = 'projects/{}/locations/{}/registries/{}/devices/{}'.format(project_id, cloud_region, registry_id, device_id)
        print('Sending message with password {}'.format(jwt))
        client = MQTTClient(client_id.encode('utf-8'),server=self.config['google_cloud_config']['mqtt_bridge_hostname'],port=self.config['google_cloud_config']['mqtt_bridge_port'],user=b'ignored',password=jwt.encode('utf-8'),ssl=True)
        client.set_callback(on_message)
        client.connect()
        client.subscribe('/devices/{}/config'.format(device_id), 1)
        client.subscribe('/devices/{}/commands/#'.format(device_id), 1)
        return client

    def connect_mqtt(self):
        self.jwt = self.create_jwt(self.config['google_cloud_config']['project_id'], self.config['jwt_config']['private_key'], self.config['jwt_config']['algorithm'], self.config['jwt_config']['token_ttl'])
        self.client = self.get_mqtt_client(self.config['google_cloud_config']['project_id'], self.config['google_cloud_config']['cloud_region'], self.config['google_cloud_config']['registry_id'], self.config['google_cloud_config']['device_id'], self.jwt)

    def reconnect(self):
        if self.is_connected() is False:
            self.connect_wifi()
            #Need to be connected to the internet before setting the local RTC.
            self.set_time()
            self.connect_mqtt()

    def read_input(self):
        return { "h": self.sensor.humidity,
                 "t": self.sensor.temperature }

    def loop(self):
        last_time = 0
        while True:
            try:
                self.reconnect()
                if utime.time() - last_time > self.config['device_config']['read_interval']:
                    last_time = utime.time() 
                    data = self.read_input()
                    message = {
                        'device_id': self.config['google_cloud_config']['device_id'],
                        'ts': utime.time(),
                        'data': data
                    }
                    print("Publishing message 1: "+str(ujson.dumps(message)))
                    self.led_pin.value(1)
                    mqtt_topic = '/devices/{}/{}'.format(self.config['google_cloud_config']['device_id'], 'events')
                    self.client.publish(mqtt_topic.encode('utf-8'), ujson.dumps(message).encode('utf-8'))
                    self.led_pin.value(0)

                self.client.check_msg() # Check for new messages on subscription
            except Exception as e:
                print("Exception: " + str(e))

            utime.sleep(1)  # Delay for 900 seconds.

device = None

def on_message(topic, message):
    return device.on_message(topic, message)

if __name__ == "__main__":
    device = Device()
    device.loop()