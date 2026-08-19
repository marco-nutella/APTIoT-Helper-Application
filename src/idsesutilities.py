from enum import Enum

class Protocols(Enum):
    WEP = ("WEP", 10)
    WPA = ("WPA", 10)
    WPA2 = ("WPA2", 5)
    WPA3 = ("WPA3", 2)
    BLE = ("Bluetooth Low Energy", 3)
    ZIGBEE = ("ZigBee", 5)
    LORAWAN = ("LoRaWAN", 1)
    NBIOT = ("NB-IoT", 7)
    RFID = ("RFID", 8)
    PROPRIETARY = ("Proprietary", 10)
    UNKNOWN = ("Unknown", 10)

class RiskEnvironment(Enum):
    PERSONAL = 1.0
    ORGANIZATIONAL = 1.3
    MILITARY = 1.4
    INFRASTRUCTURAL = 1.5

class RiskCriticality(Enum):
    LOW = 1.0
    MEDIUM = 1.2
    HIGH = 1.3
    CRITICAL = 1.5