"""
syslog.py

An ansible-rulebook event source module for receiving events via a syslog.

Arguments:
    host: The hostname to listen to. Set to 0.0.0.0 to listen on all
          interfaces. Defaults to 127.0.0.1
    port: The TCP port to listen to.  Defaults to 1514

"""


"""
              0             kernel messages
              1             user-level messages
              2             mail system
              3             system daemons
              4             security/authorization messages
              5             messages generated internally by syslogd
              6             line printer subsystem
              7             network news subsystem
              8             UUCP subsystem
              9             clock daemon
             10             security/authorization messages
             11             FTP daemon
             12             NTP subsystem
             13             log audit
             14             log alert
             15             clock daemon (note 2)
             16             local use 0  (local0)
             17             local use 1  (local1)
             18             local use 2  (local2)
             19             local use 3  (local3)
             20             local use 4  (local4)
             21             local use 5  (local5)
             22             local use 6  (local6)
             23             local use 7  (local7)


              0       Emergency: system is unusable
              1       Alert: action must be taken immediately
              2       Critical: critical conditions
              3       Error: error conditions
              4       Warning: warning conditions
              5       Notice: normal but significant condition
              6       Informational: informational messages
              7       Debug: debug-level messages

"""



# from __future__ import (absolute_import, division, print_function)


# __metaclass__ = type



# import asyncio
# import json
# import logging
# from typing import Any, Dict
# import re


# def parse(str_input):
#     """
#     Parse a string in CEF format and return a dict with the header values
#     and the extension data.
#     """

#     logger = logging.getLogger()
#     # Create the empty dict we'll return later
#     values = dict()

#     # This regex separates the string into the CEF header and the extension
#     # data.  Once we do this, it's easier to use other regexes to parse each
#     # part.
#     header_re = r'((CEF:\d+)([^=\\]+\|){,7})(.*)'

#     res = re.search(header_re, str_input)

#     if res:
#         header = res.group(1)
#         extension = res.group(4)

#         # Split the header on the "|" char.  Uses a negative lookbehind
#         # assertion to ensure we don't accidentally split on escaped chars,
#         # though.
#         spl = re.split(r'(?<!\\)\|', header)

#         # If the input entry had any blanks in the required headers, that's wrong
#         # and we should return.  Note we explicitly don't check the last item in the
#         # split list becuase the header ends in a '|' which means the last item
#         # will always be an empty string (it doesn't exist, but the delimiter does).
#         if "" in spl[0:-1]:
#             logger.warning("Blank field(s) in CEF header. Is it valid CEF format?")
#             return None

#         # Since these values are set by their position in the header, it's
#         # easy to know which is which.
#         values["DeviceVendor"] = spl[1]
#         values["DeviceProduct"] = spl[2]
#         values["DeviceVersion"] = spl[3]
#         values["DeviceEventClassID"] = spl[4]
#         values["Name"] = spl[5]
#         values["DeviceName"] = spl[5]
#         if len(spl) > 6:
#             values["Severity"] = spl[6]
#             values["DeviceSeverity"] = spl[6]

#         # The first value is actually the CEF version, formatted like
#         # "CEF:#".  Ignore anything before that (like a date from a syslog message).
#         # We then split on the colon and use the second value as the
#         # version number.
#         cef_start = spl[0].find('CEF')
#         if cef_start == -1:
#             return None
#         (cef, version) = spl[0][cef_start:].split(':')
#         values["CEFVersion"] = version

#         # The ugly, gnarly regex here finds a single key=value pair,
#         # taking into account multiple whitespaces, escaped '=' and '|'
#         # chars.  It returns an iterator of tuples.
#         spl = re.findall(r'([^=\s]+)=((?:[\\]=|[^=])+)(?:\s|$)', extension)
#         for i in spl:
#             # Split the tuples and put them into the dictionary
#             values[i[0]] = i[1]

#         # Process custom field labels
#         for key in list(values.keys()):
#             # If the key string ends with Label, replace it in the appropriate
#             # custom field
#             if key[-5:] == "Label":
#                 customlabel = key[:-5]
#                 # Find the corresponding customfield and replace with the label
#                 for customfield in list(values.keys()):
#                     if customfield == customlabel:
#                         values[values[key]] = values[customfield]
#                         del values[customfield]
#                         del values[key]
#     else:
#         # return None if our regex had now output
#         # logger.warning('Could not parse record. Is it valid CEF format?')
#         return None

#     # Now we're done!
#     logger.debug("Returning values: %s", str(values))
#     return values


# class SyslogProtocol(asyncio.DatagramProtocol):
#     def __init__(self, edaQueue):
#         super().__init__()
#         self.edaQueue = edaQueue

#     def connection_made(self, transport) -> "Used by asyncio":
#         self.transport = transport

#     def datagram_received(self, data, addr):
#         asyncio.get_event_loop().create_task(self.datagram_received_async(data, addr))

#     async def datagram_received_async(self, indata, addr) -> "Main entrypoint for processing message":
#         # Syslog event data received, and processed for EDA
#         logger = logging.getLogger()
#         rcvdata = indata.decode()
#         logger.info("Received Syslog message: %s", rcvdata)
#         data = parse(rcvdata)

#         if data is None:
#             # if not CEF, we will try JSON load of the text from first curly brace
#             try:
#                 value = rcvdata[rcvdata.index("{"):len(rcvdata)]
#                 # logger.info("value after encoding:%s", value1)
#                 data = json.loads(value)
#                 # logger.info("json:%s", data)
#             except json.decoder.JSONDecodeError as jerror:
#                 logger.error(jerror)
#                 data = rcvdata
#             except UnicodeError as e:
#                 logger.error(e)

#         if data:
#             # logger.info("json data:%s", data)
#             queue = self.edaQueue
#             await queue.put({"cyberark": data})


# async def main(queue: asyncio.Queue, args: Dict[str, Any]):
#     logger = logging.getLogger()

#     loop = asyncio.get_event_loop()
#     host = args.get("host") or '0.0.0.0'
#     port = args.get("port") or 1514
#     transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
#         lambda: SyslogProtocol(queue),
#         local_addr=((host, port)))
#     logger.info("Starting cyberark.pas.syslog [Host=%s, port=%s]", host, port)
#     try:
#         while True:
#             await asyncio.sleep(3600)  # Serve for 1 hour.
#     finally:
#         transport.close()


import asyncio
import logging
import re
from typing import Any, Dict

"""
SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
4 	auth",
5 	syslog",
6 	lpr",
7 	news",
8 	uucp",
9 	cron",
10 	authpriv",
11 	ftp",
12 	ntp",
13 	security",
14 	console",
15 	solaris-cron",
16–23 	local0 – local7 	Locally used facilities
}
"""

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, edaQueue):
        """Initialize for Event-Driven Ansible."""
        super().__init__()
        self.edaQueue = edaQueue

    def connection_made(self, transport):
        """Connection manager."""
        self.transport = transport

    def datagram_received(self, data, addr):
        """Datagram manager."""
        asyncio.get_event_loop().create_task(self.payload_processor(data, addr))

    async def payload_processor(self, data, addr):
        """Process syslog packet."""
        raw = data.decode()
        facility = None
        severity = None
        version = None
        hostname = None
        application = None
        process_id = None
        message_id = None
        message = raw
        message_format = None
        encoding = None
        full_data = None
        data_format = None
        timestamp = None
        host = None
        
        logging.info("Received Syslog message: %s", raw)

        # Parsing RFC5424 format
        result = re.match(r"<(?P<prival>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<host>\S+) (?P<application>\S+) (?P<process_id>\S+) (?P<message_id>\S+) (?P<message>.*)", raw)
        if result:
            parsed_data = result.groupdict()
            try:
                message_format = "rfc5424"
                prival = int(parsed_data.get("prival"))
                facility = int(prival/8)
                severity = int(prival%8)
                version = int(parsed_data.get("version"))
                timestamp = parsed_data.get("timestamp")
                host = parsed_data.get("host")
                application = parsed_data.get("appplication") if parsed_data.get("appplication") != "-" else None
                process_id = int(parsed_data.get("process_id")) if parsed_data.get("process_id") != "-" else None
                message_id = int(parsed_data.get("message_id")) if parsed_data.get("message_id") != "-" else None
                message = parsed_data.get("message")
            except ValueError:
                # RFC5424 parsing failure
                logging.warning("Message is not RFC5424 compliant")

        # Parsing Cisco format
        # <133>46: 169.254.1.21: *Dec 11 10:30:05.476: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # <133>47: *Dec 11 10:31:00.332: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # <133>Dec 11 11:03:00 169.254.1.21 : *Dec 11 11:02:59.934: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # <133>: *Dec 11 10:31:50.813: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # <133>: *Mar  1 18:48:50.483 UTC: %SYS-5-CONFIG_I: Configured from console by vty2 (10.34.195.36)
        # <133>: 00:00:46: %LINK-3-UPDOWN: Interface Port-channel1, changed state to up
        result = re.match(r"<(?P<prival>\d+)>((?P<message_id>\S+)\s*: )?((?P<host>\S+)\s*: )?\*?(?P<timestamp>.*)\s*: %(?P<facility>[^-]+)-(?P<severity>\d+)-(?P<mnemonic>[^:]+): (?P<message>.*)", raw)
        if result:
            parsed_data = result.groupdict()
            try:
                message_format = "cisco"
                prival = int(parsed_data.get("prival"))
                facility = int(prival/8)
                severity = int(prival%8)
                timestamp = parsed_data.get("timestamp")
                host = parsed_data.get("host")
                message_id = int(parsed_data.get("message_id")) if parsed_data.get("message_id") else None
                message = parsed_data.get("message")
            except ValueError:
                # Cisco parsing failure
                logging.warning("Message is not Cisco compliant")

        # Format output
        output = {
            "version": version,
            "facility": facility,
            "severity": severity,
            "timestamp": timestamp,
            "host": host,
            "format": message_format,
            "message": message,
            "message_id": message_id,
            "application": application,
            "process_id": process_id,
            "raw": raw,
        }

        # Send data to Ansible
        logging.info(f"Sending to EDA {output}")
        queue = self.edaQueue
        await queue.put(output)

async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:
    """Receive events via syslog."""
    # Load or set default variables
    host = args.get("host") or "0.0.0.0"
    port = args.get("port") or 1514

    # Listening
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: SyslogUDPProtocol(queue),
        local_addr=((host, port)))
    
    # Listening
    logging.info(f"Starting daemon on {host}:{port}")
    try:
        while True:
            await asyncio.sleep(300)
    finally:
        transport.close


if __name__ == "__main__":
    # Only called when testing plugin directly, without ansible-rulebook
    # instance = os.environ.get('SN_HOST')
	# username = os.environ.get('SN_USERNAME')
	# password = os.environ.get('SN_PASSWORD')
	# table	= os.environ.get('SN_TABLE')

    class MockQueue:
        async def put(self, event):
            print(event)

    # asyncio.run(main(MockQueue(), {"instance": instance, "username": username, "password": password, "table": table}))
    # asyncio.run(main(MockQueue(), {}))
