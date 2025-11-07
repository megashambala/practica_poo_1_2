from src.prueba import *
def main(test):
    while(True):
        message_personalized = input()
        if isinstance(message_personalized,(str)):
            test.send_message(test.brodcastfffffffff,message_personalized)
        else:
            if message_personalized==0:
                break
if __name__ == "__main__":
    test=MQTT_Meshtastic()
    main(test)
