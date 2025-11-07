import json
import paho.mqtt.client as mqtt

class MQTT_Sensores:

    def __init__(self):
        self.broker = "broker.emqx.io"
        self.port = 1883
        self.topics = ["sensor/data/sen55", "sensor/data/gas_sensor"]
        self.client = mqtt.Client()

    # Asignar las funciones de callback
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        # Conectar al broker MQTT
        self.client.connect(self.broker, self.port, 60)
        # Configuración del cliente MQTT


# Callback cuando se establece la conexión con el broker
    def on_connect(self,client, userdata, flags, rc):
        if rc == 0:
            print("Conexión exitosa al broker MQTT")
            # Suscribirse a los temas
            for topic in self.topics:
                client.subscribe(topic)
                print(f"Suscrito al tema '{topic}'")
        else:
            print(f"Error de conexión, código: {rc}")

    # Callback cuando se recibe un mensaje en los temas suscritos
    def on_message(self,client, userdata, msg):
        print(f"Mensaje recibido en el tema '{msg.topic}':")
        print(msg.payload.decode("utf-8"))

        try:
            # Decodificar y convertir el mensaje de JSON a diccionario
            payload = json.loads(msg.payload.decode("utf-8"))
            print(json.dumps(payload, indent=4))  # Mostrar el mensaje formateado
        except json.JSONDecodeError as e:
            print(f"Error decodificando JSON: {e}")


    def run(self):
        # Bucle principal para mantener la conexión y escuchar mensajes
        print("Esperando mensajes... Presiona Ctrl+C para salir")
        try:
            self.client.loop_forever()  # Mantener el cliente en ejecución
        except KeyboardInterrupt:
            print("Desconectando del broker...")
            self.client.disconnect()

prueba = MQTT_Sensores()
prueba.run()