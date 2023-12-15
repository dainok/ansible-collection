"""
syslog.py

An ansible-rulebook event source module for receiving events via a syslog.

Arguments:
    host: The hostname to listen to. Set to 0.0.0.0 to listen on all
          interfaces. Defaults to 127.0.0.1
    port: The TCP port to listen to.  Defaults to 1514
"""

import asyncio
import logging
import re
from typing import Any, Dict

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
        # {'prival': '133', 'message_id': '46', 'host': '169.254.1.21', 'timestamp': 'Dec 11 10:30:05.476', 'facility': 'SYS', 'severity': '5', 'mnemonic': 'CONFIG_I', 'message': 'Configured from console by admin on vty0 (169.254.1.1)'}
        # <133>47: *Dec 11 10:31:00.332: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # {'prival': '133', 'message_id': '47', 'host': None, 'timestamp': 'Dec 11 10:31:00.332', 'facility': 'SYS', 'severity': '5', 'mnemonic': 'CONFIG_I', 'message': 'Configured from console by admin on vty0 (169.254.1.1)'}
        # <133>Dec 11 11:03:00 169.254.1.21 : *Dec 11 11:02:59.934: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # {'prival': '133', 'message_id': None, 'host': '169.254.1.21', 'timestamp': 'Dec 11 11:02:59.934', 'facility': 'SYS', 'severity': '5', 'mnemonic': 'CONFIG_I', 'message': 'Configured from console by admin on vty0 (169.254.1.1)'}
        # <133>: *Dec 11 10:31:50.813: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (169.254.1.1)
        # {'prival': '133', 'message_id': None, 'host': None, 'timestamp': ': *Dec 11 10:31:50.813', 'facility': 'SYS', 'severity': '5', 'mnemonic': 'CONFIG_I', 'message': 'Configured from console by admin on vty0 (169.254.1.1)'}
        # <133>: *Mar  1 18:48:50.483 UTC: %SYS-5-CONFIG_I: Configured from console by vty2 (10.34.195.36)
        # {'prival': '133', 'message_id': None, 'host': None, 'timestamp': ': *Mar  1 18:48:50.483 UTC', 'facility': 'SYS', 'severity': '5', 'mnemonic': 'CONFIG_I', 'message': 'Configured from console by vty2 (10.34.195.36)'}
        # <133>: 00:00:46: %LINK-3-UPDOWN: Interface Port-channel1, changed state to up
        result = re.match(r"<(?P<prival>\d+)>(\s*[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+\s*)?((?P<message_id>\d+)\s*: )?((?P<host>\d+\.\d+\.\d+.\d+)\s*: )?\*?(?P<timestamp>.*)\s*: %(?P<facility>[^-]+)-(?P<severity>\d+)-(?P<mnemonic>[^:]+): (?P<message>.*)", raw)
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
        if host:
            # Limit the inventory for the action
            output["meta"] = {"hosts": host}

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
