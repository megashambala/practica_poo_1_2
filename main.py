from src.prueba import *
def main():
    while(True):
        message_personalized = input()
        if isinstance(message_personalized,(str)):
            message_personalized.send_message()
        else:
            if message_personalized==0:
                break
if __name__ == "__main__":
    test=MQTT_Meshtastic()
    test=main()
