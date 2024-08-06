# This is a helper file for the Bluebugging service

# Function to send the AT command and receive the response
def send_recv_at_cmd(sock, cmd):
   
    # send the AT command
    print(f"Sending command: {cmd}")
    sock.send(cmd + "\r") # AT commands end with "\r"

    # receive the response
    response = sock.recv(1024)
    response_str = response.decode('utf-8')

    return response_str

# Function to parse the listed messages
def parse_message_list_response(response: str):
    response_lines = response.split("\n")
    dict = {}
    last_index = None
    
    for line in response_lines:
        if line == response_lines[-1] and line == "OK":
            continue
            # The last line of the response is "OK", this is not a message
        
        if line.startswith("+CMGL:"): # parse message info
            # get rid of the start and split the line into index and message
            message_parts = line.replace("+CMGL: ", "").split(",", 1) 
            last_index = message_parts[0]
            inner_dict = {}
            inner_dict["info"] = message_parts[1]
            dict[last_index] = inner_dict

        else: # parse the message data
            # if the message data has multiple line, append the lines
            if "data" in dict[last_index]:
                dict[last_index]["data"] += "\n" + line 

            # else add the line to the dict
            else:
                dict[last_index]["data"] = line
        
    return dict

# Fention to parse the list of storages
def parse_storages(response):
    # storage names are written in quotation marks
    storage_ind = [i for i, ltr in enumerate(response) if ltr == '"']
    if len(storage_ind)%2 != 0:
        print(f"response was in the wrong format, response is: {response}")
    print(storage_ind)
    memories = []
    i = 0
    while i < len(storage_ind):
        print(i)
        first_char = storage_ind[i] + 1
        i+=1
        last_char = storage_ind[i]
        memory = response[first_char:last_char]
        memories.append(memory)
        i+=1
    memories = list(dict.fromkeys(memories)) # remove duplicates
    return memories