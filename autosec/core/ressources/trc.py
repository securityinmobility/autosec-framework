from .base import AutosecRessource

class TRCData(AutosecRessource):
    """
    Read .trc files with the column order (N,O,T,I,d,l,D)
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.start_time = 0
        self.columns = []
        self.filename = ""
        self.header_list = ["Message Number", "Time offset [ms]", "Type", "ID [hex]", "Rx/Tx", "Data length", "Data [hex]"]
        self.data_lines = []
        self.__load()

    def get_head_info(self) -> list:
        return [self.start_time, self.columns, self.filename, self.header_list]

    def get_data(self) -> list:
        return self.data_lines

    def __parse_data(self, line: list) -> list:
        data = line.strip().split()
        dicct = {} 
        dicct["message number"] = data[0]
        dicct["time offset"] = float(data[1])
        dicct["type"] = data[2]
        dicct["ID"] = data[3]
        dicct["Rx/Tx"] = data[4]
        dicct["data length"] = [5]
        dicct["data [hex]"] = bytes.fromhex(" ".join(data[6::]))
        self.data_lines.append(dicct)

    def __parse_head(self, line: list):
        line = " ".join(line.split(";")[1::]).strip()
        if "starttime" in line.lower():
            self.start_time = line.split("=")[1]
        elif "column" in line.lower():
            self.columns = line.split("=")[1].split(",")
        elif ".trc" in line.lower():
            self.filename = line.split("\\")[-1]

    def __load(self):
        if not self.filepath.endswith(".trc"):
            print("Wrong file format.")
            exit

        with open(self.filepath, 'r') as f:
            contents = f.read()
        contents = contents.split("\n")
        for line in contents:
            if line.startswith(";"):
                self.__parse_head(line)
            elif line.startswith(" "):
                self.__parse_data(line)
            else:
                exit

        if self.columns != ['N', 'O', 'T', 'I', 'd', 'l', 'D']:
            print("Wrong columns.")
            exit
