"""
An ansible-rulebook event source module for receiving events via a syslog.

Arguments:
    host: The hostname to listen to. Set to 0.0.0.0 to listen on all
          interfaces. Defaults to 127.0.0.1
    port: The TCP port to listen to.  Defaults to 1514
"""

import asyncio
import logging
import re
from typing import Any


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Manage Syslog UDP packets."""

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
        logging.info("Received Syslog message: %s", raw)

        # Parsing
        result = re.match(
            r"<(?P<prival>\d+)>(?P<version>\d+): (?P<host>\w+): (?P<seq>\d+): (?P<timestamp>\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\.\d+): %(?P<facility>\w+)-(?P<severity>\d+)-(?P<mnemonic>[\w_]+): (?P<message>.+)",
            raw,
        )
        if result:
            parsed_data = result.groupdict()
            try:
                prival = int(parsed_data.get("prival"))
                version = int(parsed_data.get("version"))
                host = parsed_data.get("host").lower() + ".example.com"
                seq = int(parsed_data.get("seq"))
                timestamp = parsed_data.get("timestamp")
                # facility = int(prival / 8)
                facility = parsed_data.get("facility")
                # severity = int(prival % 8)
                severity = parsed_data.get("severity")
                mnemonic = parsed_data.get("mnemonic")
                message = parsed_data.get("message")
            except ValueError:
                # Cisco parsing failure
                logging.warning("Message is not Cisco compliant")
                return

        # Format output
        output = {
            "prival": prival,
            "version": version,
            "host": host,
            "seq": seq,
            "timestamp": timestamp,
            "facility": facility,
            "severity": severity,
            "mnemonic": mnemonic,
            "message": message,
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
        lambda: SyslogUDPProtocol(queue), local_addr=((host, port))
    )

    # Listening
    logging.info(f"Starting daemon on {host}:{port}")
    try:
        while True:
            await asyncio.sleep(300)
    finally:
        transport.close


if __name__ == "__main__":
    # Only called when testing plugin directly, without ansible-rulebook
    class MockQueue:
        """Test class."""

        async def put(self, event):
            """Print the event."""
            print(event)
