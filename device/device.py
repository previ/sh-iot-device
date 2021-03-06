
import machine
import esp32
from third_party import string
import network
import socket
import os
import sys
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

epoch_offset = 946684800

class Device():
    instance = None

    @classmethod
    def get_instance(cls, config_data=None):
        if not cls.instance:
            cls.instance = Device(config_data)
        return cls.instance

    def __init__(self, config_data):
        self.config = config_data
        self.sta_if = network.WLAN(network.STA_IF)
        self.ota = ota_updater.OTAUpdater(github_repo=self.config['ota_config']['repo_url'], 
                                          main_repo_dir=self.config['ota_config']['repo_path'],
                                          main_dir='/',
                                          headers={'Authorization': 'token {}'.format(self.config['ota_config']['repo_token'])})
        self.jwt = None
        self.client = None
        self.sensor = htu21d.HTU21D(22,21)
        self.outputs = {'do1': machine.Pin(self.config['device_config']['do1_pin'], Pin.OUT),
                        'do2': machine.Pin(self.config['device_config']['do2_pin'], Pin.OUT),
                        'do3': machine.Pin(self.config['device_config']['do3_pin'], Pin.OUT)}

    def on_message(self, topic, message):
        try:
            print((topic, message))
            message_json = ujson.loads(message.decode('utf-8'))
            if 'config' in topic:
                self.config.update(message_json)
                print("updated config: " + str(self.config))
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
                    self.ota.set_check_update()
                    utime.sleep(1) # let mqtt client deliver the ack
                    machine.reset()
                if message_json.get('cmd') == "set_state":
                    output_id = message_json.get('output_id')
                    state = message_json.get('state')
                    self.write_output(output_id, state.get('state'))
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

    def disconnect_wifi(self):
        print('disconnecting to network...')
        self.sta_if.disconnect()
        self.sta_if.active(False)

    def disconnect(self):
        try:
            self.client.disconnect()
            self.client.close()
        except Exception:
            pass
        self.client = None
        self.jwt = None
        self.disconnect_wifi()

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
        try:
            self.jwt = self.create_jwt(self.config['google_cloud_config']['project_id'], self.config['jwt_config']['private_key'], self.config['jwt_config']['algorithm'], self.config['jwt_config']['token_ttl'])
            print("jwt ok")
        except Exception as e:
            print("connect_mqtt.jwt.Exception: " + str(e))
        try:
            self.client = self.get_mqtt_client(self.config['google_cloud_config']['project_id'], self.config['google_cloud_config']['cloud_region'], self.config['google_cloud_config']['registry_id'], self.config['google_cloud_config']['device_id'], self.jwt)
            print("mqtt connected")
        except Exception as e:
            print("connect_mqtt.client.Exception: " + str(e))

    def reconnect(self):
        if self.is_connected() is False:
            self.connect_wifi()
            #Need to be connected to the internet before setting the local RTC.
            self.set_time()

            if self.ota.get_check_update():
                if self.ota.check_for_update_to_install_during_next_reboot():
                    machine.reset()

        if self.client is None:
            self.connect_mqtt()

    def read_input(self, input_id):
        return { "s1h": self.sensor.humidity,
                 "s1t": self.sensor.temperature }[input_id]        

    def write_output(self, output_id, state):
        self.outputs.get(output_id).value(state)

    def loop(self):
        last_time = 0
        while True:
            try:
                self.reconnect()
                if utime.time() - last_time > self.config['device_config']['read_interval']:
                    for input_id in ['s1h', 's1t']:
                        last_time = utime.time() 
                        data = self.read_input(input_id)
                        message = {
                            'ts': utime.time() + epoch_offset,
                             'home_id': self.config['google_cloud_config']['home_id'],
                             'device_id': self.config['google_cloud_config']['device_id'],
                             'input_id': input_id,
                             'data': data
                        }
                        print("Publishing message: "+str(ujson.dumps(message)))
                        self.write_output('do1', True)
                        mqtt_topic = '/devices/{}/{}'.format(self.config['google_cloud_config']['device_id'], 'events')

                        try:
                            self.client.publish(mqtt_topic.encode('utf-8'), 
                                                ujson.dumps(message).encode('utf-8'))
                        except Exception as e:
                            print("publish.Exception: " + str(e))
                            self.disconnect()                        

                        self.write_output('do1', False)

                try:
                    self.client.check_msg() # Check for new messages on subscription
                except Exception as e:
                    print("check_msg.Exception: " + str(e))
                    self.disconnect()

            except Exception as e:
                print("Exception: " + str(e))

            utime.sleep(1)  # Delay for 1 second(s).

def on_message(topic, message):
    return Device.get_instance().on_message(topic, message)
