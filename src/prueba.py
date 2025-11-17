#!/usr/bin/env python3
"""
Powered by Meshtastic™ https://meshtastic.org/
"""

from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2
from meshtastic import BROADCAST_NUM, protocols
import paho.mqtt.client as mqtt
import random
import time
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import re
import logging
import os
import pathlib
class MQTT_Meshtastic:
    def __init__(self):
#### Debug Options
        self.debug = True
        self.autoauto_reconnect = True
        self.auto_reconnect_delay = 1 # seconds
        self.print_service_envelope = False
        self.print_message_packet = False


        self.brodcast = BROADCAST_NUM
        self.print_node_info =  True
        self.print_node_position = True
        self.print_node_telemetry = True

        ### Default settings
        self.mqtt_broker = "mqtt.meshtastic.org"
        self.mqtt_port = 1883
        self.mqtt_username = "meshdev"
        self.mqtt_password = "large4cats"
        self.root_topic = "msh/EU_868/ES/2/e/"
        self.channel = "TestMQTT"
        self.key = "ymACgCy9Tdb8jHbLxUxZ/4ADX+BWLOGVihmKHcHTVyo="
        self.message_text = "Ordenador de Ekaitz"

        # Generate 4 random hexadecimal characters to create a unique node name
        self.node_name = "!abcdc0c8"
        self.node_number = int(self.node_name.replace("!", ""), 16)
        self.global_message_id = random.getrandbits(32)
        self.client_short_name = "EIR"
        self.client_long_name = "Ekaitz"
        self.lat = "0"
        self.lon = "0"
        self.alt = "0"
        self.client_hw_model = 255

        self.tls_configured = False
        self.filename = "C:\Users\EKAITZ\OneDrive - Universidad de Burgos\AAA Sgundo Curso\POO_PRactica_1_2\Log\log.txt"
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="", clean_session=True, userdata=None)
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        #self.mesh_packet.id
        self.client.on_message = self.on_message
        self.connect_mqtt()
        
        if self.client.is_connected:
            self.send_node_info(BROADCAST_NUM, want_response=False)
            time.sleep(4)
            self.send_position(BROADCAST_NUM)
            time.sleep(4)
            self.send_message(BROADCAST_NUM, self.message_text)
            time.sleep(4)


    #################################
    ### Program variables

        self.default_key = "1PG7OiApB1nwvP+rz05pAQ==" # AKA AQ==

#################################
# Program Base Functions
    
    def set_topic(self):
        if self.debug: print("set_topic")
        node_name = '!' + hex(self.node_number)[2:]
        self.subscribe_topic = self.root_topic + self.channel + "/#"
        self.publish_topic = self.root_topic + self.channel + "/" + node_name

    def xor_hash(self,data):
        result = 0
        for char in data:
            result ^= char
        return result

    def generate_hash(self,name, key):
        replaced_key = key.replace('-', '+').replace('_', '/')
        key_bytes = base64.b64decode(replaced_key.encode('utf-8'))
        h_name = self.xor_hash(bytes(name, 'utf-8'))
        h_key = self.xor_hash(key_bytes)
        result = h_name ^ h_key
        return result


#################################
# Receive Messages

    def on_message(self,client, userdata, msg):
        se = mqtt_pb2.ServiceEnvelope()
        try:
            se.ParseFromString(msg.payload)
            if self.print_service_envelope:
                print ("")
                print ("Service Envelope:")
                print (se)
            mp = se.packet
            if self.print_message_packet: 
                print ("")
                print ("Message Packet:")
                print(mp)
        except Exception as e:
            print(f"*** ServiceEnvelope: {str(e)}")
            return
        
        if mp.HasField("encrypted") and not mp.HasField("decoded"):
            self.decode_encrypted(mp)

        # Attempt to process the decrypted or encrypted payload
        portNumInt = mp.decoded.portnum if mp.HasField("decoded") else None
        handler = protocols.get(portNumInt) if portNumInt else None

        pb = None
        if handler is not None and handler.protobufFactory is not None:
            pb = handler.protobufFactory()
            pb.ParseFromString(mp.decoded.payload)

        if pb:
            # Clean and update the payload
            pb_str = str(pb).replace('\n', ' ').replace('\r', ' ').strip()
            mp.decoded.payload = pb_str.encode("utf-8")
        print(mp)


    def decode_encrypted(self,mp):
            try:
                key_bytes = base64.b64decode(self.key.encode('ascii'))
                nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
                nonce_from_node = getattr(mp, "from").to_bytes(8, "little")
                nonce = nonce_packet_id + nonce_from_node
                cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_bytes = decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()
                data = mesh_pb2.Data()
                data.ParseFromString(decrypted_bytes)
                mp.decoded.CopyFrom(data)
            except Exception as e:
                if self.print_message_packet: print(f"failed to decrypt: \n{mp}")
                if self.debug: print(f"*** Decryption failed: {str(e)}")
                return

#################################
# Send Messages

    def direct_message(self,destination_id):
        if self.debug: print("direct_message")
        if destination_id:
            try:
                destination_id = int(destination_id[1:], 16)
                self.send_message(destination_id)
            except Exception as e:
                if self.debug: print(f"Error converting destination_id: {e}")

    def send_message(self,destination_id, message_text):
        if not self.client.is_connected():
            self.connect_mqtt()

        if message_text:
            encoded_message = mesh_pb2.Data()
            encoded_message.portnum = portnums_pb2.TEXT_MESSAGE_APP 
            encoded_message.payload = message_text.encode("utf-8")
            self.generate_mesh_packet(destination_id, encoded_message)
        else:
            return

    def send_traceroute(self,destination_id):
        if not self.client.is_connected():
            self.connect_mqtt()
        if self.debug: print(f"Sending Traceroute Packet to {str(destination_id)}")

        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TRACEROUTE_APP
        encoded_message.want_response = True

        destination_id = int(destination_id[1:], 16)
        self.generate_mesh_packet(destination_id, encoded_message)

    def send_node_info(self,destination_id, want_response):
        if self.client.is_connected():
            user_payload = mesh_pb2.User()
            setattr(user_payload, "id", self.node_name)
            setattr(user_payload, "long_name", self.client_long_name)
            setattr(user_payload, "short_name", self.client_short_name)
            setattr(user_payload, "hw_model", self.client_hw_model)

            user_payload = user_payload.SerializeToString()

            encoded_message = mesh_pb2.Data()
            encoded_message.portnum = portnums_pb2.NODEINFO_APP
            encoded_message.payload = user_payload
            encoded_message.want_response = want_response  # Request NodeInfo back
            self.generate_mesh_packet(destination_id, encoded_message)

    def send_position(self,destination_id):
        if self.client.is_connected():
            pos_time = int(time.time())
            latitude = int(float(self.lat) * 1e7)
            longitude = int(float(self.lon) * 1e7)
            altitude_units = 1 / 3.28084 if 'ft' in str(self.alt) else 1.0
            altitude = int(altitude_units * float(re.sub('[^0-9.]', '', str(self.alt))))

            position_payload = mesh_pb2.Position()
            setattr(position_payload, "latitude_i", latitude)
            setattr(position_payload, "longitude_i", longitude)
            setattr(position_payload, "altitude", altitude)
            setattr(position_payload, "time", pos_time)

            position_payload = position_payload.SerializeToString()

            encoded_message = mesh_pb2.Data()
            encoded_message.portnum = portnums_pb2.POSITION_APP
            encoded_message.payload = position_payload
            encoded_message.want_response = True

            self.generate_mesh_packet(destination_id, encoded_message)

    def generate_mesh_packet(self,destination_id, encoded_message):
        mesh_packet = mesh_pb2.MeshPacket()

        # Use the global message ID and increment it for the next call
        mesh_packet.id = self.global_message_id
        self.global_message_id += 1
        
        setattr(mesh_packet, "from", self.node_number)
        mesh_packet.to = destination_id
        mesh_packet.want_ack = False
        mesh_packet.channel = self.generate_hash(self.channel, self.key)
        mesh_packet.hop_limit = 3

        if self.key == "":
            mesh_packet.decoded.CopyFrom(encoded_message)
        else:
            mesh_packet.encrypted = self.encrypt_message(self.channel, self.key, mesh_packet, encoded_message)

        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)
        service_envelope.channel_id = self.channel
        service_envelope.gateway_id = self.node_name

        payload = service_envelope.SerializeToString()
        topic = self.publish_topic
        self.client.publish(topic, payload)

    def encrypt_message(self,channel, key, mesh_packet, encoded_message):
        mesh_packet.channel = self.generate_hash(self.channel, self.key)
        key_bytes = base64.b64decode(key.encode('ascii'))
        nonce_packet_id = mesh_packet.id.to_bytes(8, "little")
        nonce_from_node = self.node_number.to_bytes(8, "little")
        nonce = nonce_packet_id + nonce_from_node
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_bytes = encryptor.update(encoded_message.SerializeToString()) + encryptor.finalize()
        return encrypted_bytes

    def send_ack(self,destination_id, message_id):
        if self.debug: print("Sending ACK")
        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.ROUTING_APP
        encoded_message.request_id = message_id
        encoded_message.payload = b"\030\000"
        self.generate_mesh_packet(destination_id, encoded_message)


#################################
# MQTT Server 
    
    def connect_mqtt(self):

        if self.debug: print("connect_mqtt")
        if not self.client.is_connected():
            try:
                if ':' in self.mqtt_broker:
                    self.mqtt_broker,mqtt_port = self.mqtt_broker.split(':')
                    mqtt_port = int(mqtt_port)

                if self.key == "AQ==":
                    if self.debug: print("key is default, expanding to AES128")
                    self.key = "1PG7OiApB1nwvP+rz05pAQ=="

                padded_key = self.key.ljust(len(self.key) + ((4 - (len(self.key) % 4)) % 4), '=')
                replaced_key = padded_key.replace('-', '+').replace('_', '/')
                self.key = replaced_key

                self.client.username_pw_set(self.mqtt_username, self.mqtt_password)
                if self.mqtt_port == 8883 and self.tls_configured == False:
                    self.client.tls_set(ca_certs="cacert.pem", tls_version=ssl.PROTOCOL_TLSv1_2)
                    self.client.tls_insecure_set(False)
                    self.tls_configured = True
                self.client.connect(self.mqtt_broker, self.mqtt_port, 60)
                self.client.loop_start()

            except Exception as e:
                print (e)

    def disconnect_mqtt(self):
        if self.debug: print("disconnect_mqtt")
        if self.client.is_connected():
            self.client.disconnect()

    def on_connect(self,client, userdata, flags, reason_code, properties):
        self.set_topic()
        if client.is_connected():
            print("client is connected")
        
        if reason_code == 0:
            if self.debug: print(f"Connected to sever: {self.mqtt_broker}")
            if self.debug: print(f"Subscribe Topic is: {self.subscribe_topic}")
            if self.debug: print(f"Publish Topic is: {self.publish_topic}\n")
            client.subscribe(self.subscribe_topic)

    def on_disconnect(self,client, userdata, flags, reason_code, properties):
        if self.debug: print("on_disconnect")
        if reason_code != 0:
            if self.auto_reconnect == True:
                print("attempting to reconnect in " + str(self.auto_reconnect_delay) + " second(s)")
                time.sleep(self.auto_reconnect_delay)
                self.connect_mqtt()

# Funcion que he creado yo para guardar cosas en json
    def process_file(self,filename):
        try:
            if not os.path.isfile(filename):
                raise FileNotFoundError(f"El archivo {filename} no existe.")
            
            with open(filename,'r') as file:
                data = file.readlines()
            
            if not data:
                raise ValueError("El archivo está vacio.")
            
            processed_data = []
            for line in data:
                try:
                    self.message_text = str(line.strip())
                except ValueError:
                    print(f"Advertencia: {line.strip()} no es una mensaje válido y se omitirá.")
            if not processed_data:
                raise RuntimeError("No se pudieron procesar datos válidos del archivo.")
            
            print("Datos procesados con exito:",processed_data)
            return processed_data
        except (FileNotFoundError,ValueError,RuntimeError) as e:
            print(f"Error:{e}")
        except Exception as e:
            print(f"Se produjo un error inesperado :{e}")
