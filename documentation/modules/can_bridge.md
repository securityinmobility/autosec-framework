# Can_Bridge

The can_bridge module has the purpose to provide an easy way to perform Man-in-the-Middle-Attacks in CAN networks. Therefore, two distinct CAN Interfaces (Socket-CAN) are used.

In the normal operation mode, the messages are routed between the two interfaces (messages received on interface 1 are sent on interface 2 and vice versa). The module can handle multiple filters, that react to messages received on the interfaces and modify this standard behaviour. The filters can be used to send modified messages on either or both of the interface or to suppress the transfer on the other interface.

## Module Interface

By loading the module (using the utils.load_module method) a list with only one instance of the can_bridge is returned. This module implements the standard autosec_module interface.

## Module Options

The can_bridge uses three main (top-level) options described in the following sections.

### primaryInterface

|||
|---|---|
|name|primaryInterface|
|description|First Interface of the CAN Bridge|
|required|True|
|default|None|
|Type|String|

This option must be specified to run the module (otherwise `run()` will fail). It specifies the first Socket-CAN interface that is used by the module. In case an unavailable interface is specified, the `run()` call will fail as well and a warning message will appear. The interface is specified by the string-name (e.g. "can0", "vcan1" etc.).

The option is set by the standard `set_option()` call (e.g. `set_option(("primaryInterface", "vcan1"))`.

### secondaryInterface

|||
|---|---|
|name|secondaryInterface|
|description|Second Interface of the CAN Bridge|
|required|True|
|default|None|
|Type|String|

This option must be specified to run the module (otherwise `run()` will fail). It specifies the second Socket-CAN interface that is used by the module. The behaviour is exactly the same as with the primaryInterface.

### filters

This option specifes the filters, that are used.

|||
|---|---|
|name|filters|
|description|Filters that can intercept the communication|
|required|False|
|default|`([][])`|
|Type|Tuple of Lists of callbacks `(x,y -> (a,b,c))`|

The structure of this options is as follows: The first List of the tuple contains all filters for the first interface (primaryInterface), the second list for the second interface (secondaryInterface). In case a message is received on eihter of the interfaces, all filters in the list are invoked with the CAN message Identifier and data (identifier, data). This callbacks return a tuple with three values. The first value specifies if this filter brings a specific treatment for the received message. If no filter returns a `True` in the first value, the message will be sent without modification on the other interface. If `True` is returned, the value on the second place specifies the message to be sent on the first interface (Tuple with id and data), the third value reprensents the message to be sent on the second interface (again a Tuple with id and data). If either of the last two values contains `None` no message will be sent.

#### Examples:

Stop messages received on interface 1 to be sent on interface 2
```python
set_option(("filters", ([lambda id, data: (True, None, None)],[])))
```

Return the message on interface as received on both interfaces
```python
set_option(("filters", ([lambda id, data: (True, (id, data), (id, data))],[])))
```

Do more complex stuff with a message received on interface 2

```python
def complex_stuff(id, data):
    if id is 0x123:
        return (True, (0x567, b'ABC'), (0x876, b'123'))
    else:
        return (False, None, None)  #be sure to use standard behavior for all other messages

set_option(("filters", ([],[complex_stuff])))
```

## Known bugs / open issues

- ISO-TP is not supported by now
- Extended identifier behaviour unclear
