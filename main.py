from src.prueba import *
def main(test):
    while(True):
        message_personalized = input("Escribe aqui:")
        if isinstance(message_personalized,(str)):
            test.send_message(test.brodcast,message_personalized)
        else:
            if message_personalized==0:
                break
        test.process_file(test.filename)
if __name__ == "__main__":
    test=MQTT_Meshtastic()
    main(test)
