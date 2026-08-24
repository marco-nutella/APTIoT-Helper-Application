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
    PERSONAL = ("Personal", 1.0)
    ORGANIZATIONAL = ("Organizational", 1.3)
    MILITARY = ("Military", 1.4)
    INFRASTRUCTURAL = ("Infrastructural", 1.5)

class RiskCriticality(Enum):
    LOW = ("Low", 1.0)
    MEDIUM = ("Medium", 1.2)
    HIGH = ("High", 1.3)
    CRITICAL = ("Critical", 1.5)

class RiskAcceptance:
    matrix = {
        RiskEnvironment.PERSONAL:{
            RiskCriticality.LOW:9.0,
            RiskCriticality.MEDIUM:7.0,
            RiskCriticality.HIGH:5.0,
            RiskCriticality.CRITICAL:4.0
        },
        RiskEnvironment.ORGANIZATIONAL:{
            RiskCriticality.LOW:6.0,
            RiskCriticality.MEDIUM:4.0,
            RiskCriticality.HIGH:3.0,
            RiskCriticality.CRITICAL:2.0
        },
        RiskEnvironment.MILITARY:{
            RiskCriticality.LOW:4.0,
            RiskCriticality.MEDIUM:3.0,
            RiskCriticality.HIGH:0.0,
            RiskCriticality.CRITICAL:0.0
        },
        RiskEnvironment.INFRASTRUCTURAL:{
            RiskCriticality.LOW:3.0,
            RiskCriticality.MEDIUM:2.0,
            RiskCriticality.HIGH:0.0,
            RiskCriticality.CRITICAL:0.0
        },
    }