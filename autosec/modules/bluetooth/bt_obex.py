import struct
from PyOBEX import client, headers, responses


class TypeHeader(headers.DataHeader):
    code = 0x42

    def encode(self, data):
        if data[-1:] != b"\x00":
            data += b"\x00"
        return struct.pack(">BH", self.code, len(data) + 3) + data


class FixedClient(client.Client):
    def __init__(self, address, port):
        super().__init__(address,port)

    @staticmethod
    def _collect_parts(header_list):
        body = []
        new_headers = []
        for header in header_list:

            if isinstance(header, headers.Body):
                body.append(header.data)
            elif isinstance(header, headers.End_Of_Body):
                body.append(header.data)
            else:
                new_headers.append(header)

        return new_headers, b"".join(body)


class FixedBrowserClient(FixedClient):
    """FixedBrowserClient(FixedClient)

    client = FixedBrowserClient(address, port)

    Provides an OBEX client that can be used to browse directories on a
    server via a folder-browsing service.

    The address used is a standard six-field bluetooth address, and the port
    should correspond to the port providing the folder-browsing service.

    To determine the correct port, examine the advertised services for a
    device by calling the bluetooth.find_service() function with the
    address of the device as the only argument.
    """

    def connect(self, header_list=()):
        uuid = b"\xF9\xEC\x7B\xC4\x95\x3C\x11\xd2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
        return FixedClient.connect(self, header_list=[headers.Target(uuid)])

    def capability(self):
        """capability(self)

        Returns a capability object from the server, or the server's response
        if the operation was unsuccessful.
        """

        response = self.get(header_list=[headers.Type(b"x-obex/capability")])
        if not isinstance(response, responses.Success):
            return response
        header, data = response
        return data

    def listdir(self, name=""):
        """listdir(self, name = "")

        Requests information about the contents of the directory with the
        specified name relative to the current directory for the session.
        Returns a tuple containing the server's response and the associated
        data.

        If successful, the directory contents are returned in the form of
        an XML document as described by the x-obex/folder-listing MIME type.

        If the name is omitted or an empty string is supplied, the contents
        of the current directory are typically listed by the server.
        """

        return self.get(name, header_list=[TypeHeader(b"x-obex/folder-listing", False)])
    
class PBAPClient(FixedClient):
    """PBAPCLient(FixedClient)
        client = PBAPClient(address, port)

        The address used is a standard six-field bluetooth address, and the port
        should correspond to the port providing the folder-browsing service.

        To determine the correct port, examine the advertised services for a
        device by calling the bluetooth.find_service() function with the
        address of the device as the only argument.
    """

    def connect(self, header_list=()):
        uuid = b"\x79\x61\x35\xf0\xf0\xc5\x11\xd8\x09\x66\x08\x00\x20\x0c\x9a\x66"
        return FixedClient.connect(self, header_list=[headers.Target(uuid)])