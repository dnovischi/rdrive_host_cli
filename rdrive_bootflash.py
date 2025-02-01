#!/usr/bin/env python3
from itertools import pairwise
import serial
import argparse
import time
import bincopy
import shutil

from collections.abc import Iterable, Iterator
from itertools import islice
from typing import TypeVar

T = TypeVar("T")

def batched(iterable: Iterable[T], n: int) -> Iterator[tuple[T, ...]]:  # noqa: D103
    """Batch data into tuples of length n. The last batch may be shorter.

    Parameters
    ----------
    iterable : Iterable[T]
        The iterable to batch.
    n : int
        The batch size.

    Returns
    -------
    Iterator[tuple[T, ...]]
        An iterator over the batches.
    """
    if n < 1:
        raise ValueError("n must be at least one")  # noqa: TRY003,EM101
    it = iter(iterable)
    while batch := tuple(islice(it, n)):
        yield batch

# Config the constants
MAX_PACKET_LEN = 256
SLEEP_DURATION = 0.001
SERIAL_TIMEOUT = 0.1  
BASE_COMMAND_SIZE = 11

# Command response statuses
COMMAND_SUCCESS = 0x01
UNSUPPORTED_COMMAND = 0xFF
BAD_ADDRESS = 0xFE
BAD_LENGTH = 0xFD
VERIFY_FAIL = 0xFC

# Flash unlock key
FLASH_UNLOCK_KEY = 0x00AA0055

# Boot command values
READ_VERSION = 0x00
READ_FLASH = 0x01
WRITE_FLASH = 0x02
ERASE_FLASH = 0x03
CALC_CHECKSUM = 0x08
RESET_DEVICE = 0x09
SELF_VERIFY = 0x0A
GET_MEMORY_ADDRESS_RANGE_COMMAND = 0x0B

def get_memory_address_range(connection):
    """Get the memory address range from the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.

    Returns
    -------
    dict
        A dictionary containing the memory address range.
    """
    # The command to get the memory address range
    cmd = {
        'cmd': GET_MEMORY_ADDRESS_RANGE_COMMAND,
        'dataLength': 8,
        'unlockSequence': 0,
        'address': 0
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11],
        'programFlashStart': int.from_bytes(response[12:16], byteorder='little'),
        'programFlashEnd': int.from_bytes(response[16:20], byteorder='little')
    }

    return parsed_response

def reset_device(connection):
    """Reset the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to reset the device
    cmd = {
        'cmd': RESET_DEVICE,
        'dataLength': 0,
        'unlockSequence': 0,
        'address': 0
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)
    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11]
    }

    return parsed_response

def read_version(connection):
    """Read the version information from the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.

    Returns
    -------
    dict
        A dictionary containing the version information.
    """
    # The command to read the version
    cmd = {
        'cmd': READ_VERSION,
        'dataLength': 0,
        'unlockSequence': 0,
        'address': 0
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'version': int.from_bytes(response[11:13], byteorder='little'),
        'maxPacketLength': int.from_bytes(response[13:15], byteorder='little'),
        'unused1': int.from_bytes(response[15:17], byteorder='little'),
        'deviceId': int.from_bytes(response[17:19], byteorder='little'),
        'unused2': int.from_bytes(response[19:21], byteorder='little'),
        'eraseSize': int.from_bytes(response[21:23], byteorder='little'),
        'writeSize': int.from_bytes(response[23:25], byteorder='little'),
        'unused3': int.from_bytes(response[25:29], byteorder='little'),
        'userRsvdStartSddress': int.from_bytes(response[29:33], byteorder='little'),
        'userRsvdEndSddress': int.from_bytes(response[33:37], byteorder='little')
    }

    return parsed_response

def erase_flash(connection, address=0x2800, length=0x1):
    """Erase the flash memory of the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    address : int, optional
        The starting address to erase, by default 0x2800.
    length : int, optional
        The length of the memory to erase, by default 0x1.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to erase the flash
    cmd = {
        'cmd': ERASE_FLASH,
        'dataLength': length,
        'unlockSequence': FLASH_UNLOCK_KEY,
        'address': address
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11]
    }

    return parsed_response

def write_flash(connection, address=0x2800, data=b'\xCA\xFE\xBA\xBE\xB0\x55\xBE\xAF'):
    """Write data to the flash memory of the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    address : int, optional
        The starting address to write, by default 0x2800.
    data : bytes, optional
        The data to write, by default b'\xCA\xFE\xBA\xBE\xB0\x55\xBE\xAF'.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to write the flash
    cmd = {
        'cmd': WRITE_FLASH,
        'dataLength': len(data),
        'unlockSequence': FLASH_UNLOCK_KEY,
        'address': address
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ]) + data

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)
    
    # Debug print statement
    # print(f"Response length: {len(response)}")
    if len(response) == 0:
        raise Exception("No response received from the device")

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11]
    }

    return parsed_response

def read_flash(connection, address=0x2800, length=8):
    """Read data from the flash memory of the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    address : int, optional
        The starting address to read, by default 0x2800.
    length : int, optional
        The length of the data to read, by default 8.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to read the flash
    cmd = {
        'cmd': READ_FLASH,
        'dataLength': length,
        'unlockSequence': 0,
        'address': address
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11],
        'data': response[12:12 + length]
    }

    return parsed_response

def self_verify(connection):
    """Perform a self-verify operation on the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to self-verify
    cmd = {
        'cmd': SELF_VERIFY,
        'dataLength': 0,
        'unlockSequence': 0,
        'address': 0
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11]
    }

    return parsed_response

def calculate_checksum(connection, address=0x2800, length=8):
    """Calculate the checksum of the flash memory of the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    address : int, optional
        The starting address to calculate the checksum, by default 0x2800.
    length : int, optional
        The length of the data to calculate the checksum, by default 8.

    Returns
    -------
    dict
        A dictionary containing the response from the device.
    """
    # The command to calculate the checksum
    cmd = {
        'cmd': CALC_CHECKSUM,
        'dataLength': length,
        'unlockSequence': 0,
        'address': address
    }

    # Creating the command byte buffer
    buffer = bytes([
        cmd['cmd'],
        cmd['dataLength'] & 0xFF, 
        (cmd['dataLength'] >> 8) & 0xFF,
        cmd['unlockSequence'] & 0xFF, 
        (cmd['unlockSequence'] >> 8) & 0xFF, 
        (cmd['unlockSequence'] >> 16) & 0xFF, 
        (cmd['unlockSequence'] >> 24) & 0xFF,
        cmd['address'] & 0xFF, 
        (cmd['address'] >> 8) & 0xFF, 
        (cmd['address'] >> 16) & 0xFF, 
        (cmd['address'] >> 24) & 0xFF
    ])

    # Sending the command to the MCU / Receive the response
    connection.write(buffer)
    # time.sleep(SLEEP_DURATION)
    response = connection.read(MAX_PACKET_LEN)

    # Parsing the response
    parsed_response = {
        'cmd': response[0],
        'dataLength': int.from_bytes(response[1:3], byteorder='little'),
        'unlockSequence': int.from_bytes(response[3:7], byteorder='little'),
        'address': int.from_bytes(response[7:11], byteorder='little'),
        'success': response[11],
        'checksum': int.from_bytes(response[12:14], byteorder='little')
    }

    return parsed_response

def get_datasize(written_bytes: float) -> str:
    """Get human-readable datasize as string.

    Parameters
    ----------
    written_bytes : int
        Number of bytes written so far.

    Returns
    -------
    str
        Human-readable datasize as string.
    """
    decimals = 0

    for _prefix in ("", "Ki", "Mi"):
        next_prefix = 1000

        if written_bytes < next_prefix:
            break

        written_bytes /= 1024
        decimals = 1

    return f"{written_bytes:.{decimals}f} {_prefix}B"

def get_timer(elapsed: float) -> str:
    """Get a timer string formatted as H:MM:SS.

    Parameters
    ----------
    elapsed : float
        Time since start.

    Returns
    -------
    str
        Timer string formatted as H:MM:SS.
    """
    hours, minutes = divmod(elapsed, 3600)
    hours = int(hours)
    minutes, seconds = divmod(minutes, 60)
    minutes = int(minutes)
    seconds = int(seconds)
    return f"Elapsed Time: {hours}:{minutes:02}:{seconds:02}"


def get_bar(done_ratio: float, used_width: int) -> str:
    """Get progressbar string.

    Parameters
    ----------
    done_ratio : float
        A value between zero and one.
    used_width : int
        Number of characters already used by other elements.

    Returns
    -------
    str
        Progressbar string.
    """
    max_width = min(shutil.get_terminal_size().columns, 80)
    bar_width = max_width - used_width - 2
    done = int(bar_width * done_ratio)
    left = bar_width - done
    return "|" + done * "#" + left * " " + "|"

def print_progress(written_bytes: int, total_bytes: int, elapsed: float) -> None:
    """Print progressbar.

    Parameters
    ----------
    written_bytes : int
        Number of bytes written so far.
    total_bytes : int
        Total number of bytes to write.
    elapsed : float
        Seconds since start.
    """

    ratio = written_bytes / total_bytes
    percentage = f"{100 * ratio:.0f}%"
    datasize = get_datasize(written_bytes)
    timer = get_timer(elapsed)
    progress = get_bar(
        ratio,
        len(percentage) + len(datasize) + len(timer) + 3 * len("  "),
    )
    print(  # noqa: T201
        percentage,
        datasize,
        progress,
        timer,
        sep="  ",
        end="\n\r" if written_bytes == total_bytes else "\r",
    )

def hex_parse_packets(hexfile: str, memory_addr_range: dict, version: dict):
    """Split a HEX file into packets.

    Parameters
    ----------
    hexfile : str
        Path of a HEX file containing application firmware.
    memory_addr_range : dict
        The attributes as read by `get_memory_address_range`.
    version : dict
        The attributes as read by `read_version`.

    Returns
    -------
    total_bytes : int
        The total number of bytes in all chunks.
    packets : list
        Appropriatelly sized packets of data, suitable for writing in a loop with
        `write_flash`.

    Raises
    ------
    bincopy.Error
        If HEX file contains no data in program memory range.
    """
    hexdata = bincopy.BinFile()
    hexdata.add_microchip_hex_file(hexfile)
    hexdata.crop(memory_addr_range['programFlashStart'], memory_addr_range['programFlashEnd'])
    chunk_size = version['maxPacketLength'] - BASE_COMMAND_SIZE
    chunk_size -= chunk_size % version['writeSize']
    chunk_size //= hexdata.word_size_bytes
    total_bytes = len(hexdata) * hexdata.word_size_bytes

    if total_bytes == 0:
        msg = "HEX file contains no data within program memory range"
        raise bincopy.Error(msg)

    total_bytes += (version['writeSize'] - total_bytes) % version['writeSize']
    align = version['writeSize'] // hexdata.word_size_bytes
    packets = []

    chunks = hexdata.segments.chunks(chunk_size, align,padding=b"\xff\xff")
    for chunk in chunks:
        address = chunk.address
        data = chunk.data
        packets.append({'address': address, 'data': data})

    return total_bytes, packets

def calculate_local_checksum(data: bytes) -> int:
    """Calculate the local checksum of the given data.

    Parameters
    ----------
    data : bytes
        The data to calculate the checksum for.

    Returns
    -------
    int
        The calculated checksum.
    """
    chksum = 0
    extended_address_width = 4

    for batch in batched(data, extended_address_width):
        chksum += batch[0] + (batch[1] << 8) + batch[2]

    return chksum & 0xFFFF

def erase(connection, memory_addr_range, version):    
    """Erase the flash memory of the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    memory_addr_range : dict
        The memory address range of the device.
    version : dict
        The version information of the device.
    """
    page_boundaries = range(memory_addr_range['programFlashStart'], memory_addr_range['programFlashEnd'], version['eraseSize'])
    total_pages = len(page_boundaries) - 1

    print("Erasing flash...")
    time_start = time.time()
    for erased_pages, page in enumerate(pairwise(page_boundaries), start=1):
        start, end = page
        length = version['eraseSize']
        
        if(end - start) % length != 0:
            raise Exception("Invalid erase length")
        
        response = erase_flash(connection, start, (end-start)//length)
        # response = {}
        # response['success'] = COMMAND_SUCCESS
        if response['success'] != COMMAND_SUCCESS:
            raise Exception(f"Failed to erase flash at address {start:04X}")
        
        print_progress(
                erased_pages * length,
                total_pages * length,
                time.time() - time_start,
            )
    # print("Erasing done")    

def flash(connection, memory_addr_range, version, hexfile, checksum=False):
    """Flash the firmware to the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    memory_addr_range : dict
        The memory address range of the device.
    version : dict
        The version information of the device.
    hexfile : str
        The path to the HEX file containing the firmware.
    checksum : bool, optional
        Whether to verify the checksum after flashing, by default False.
    """
    # Load the firmware image and split it into packets.
    total_bytes, packets = hex_parse_packets(hexfile, memory_addr_range, version)
    time_start = time.time()

    
    # Erase the flash
    erase(connection, memory_addr_range, version)
    

    # Flash the firmware
    print("Flashing firmware...")
    for packet_num, packet in enumerate(packets, start=1):
        address = packet['address']
        data = packet['data']
        response = write_flash(connection, address, data)
        # response = {}
        # response['success'] = COMMAND_SUCCESS

        if response['success'] != COMMAND_SUCCESS:
            raise Exception(f"Failed to write flash at address {address:04X}")
        
        print_progress(packet_num * len(data), total_bytes, time.time() - time_start)
    print_progress(total_bytes, total_bytes, time.time() - time_start)
    # print("Flash successful")
    

    # Verify the image if requested
    if checksum:

        time_start = time.time()

        print("Verifying image...")
        for packet_num, packet in enumerate(packets, start=1):
            address = packet['address']
            data = packet['data']
            local_checksum = calculate_local_checksum(data)
        
            
            response = calculate_checksum(connection, address, len(data))
            device_checksum = response['checksum']
            
            if packet_num != 1 and local_checksum != device_checksum:
                print(f"Checksum mismatch at address {address:04X}: {local_checksum:04X} != {device_checksum:04X}")
            
            print_progress(packet_num * len(data), total_bytes, time.time() - time_start)

        print_progress(total_bytes, total_bytes, time.time() - time_start)   
        # print("Verification successful")
    print('Done')


def self_test(connection, memory_addr_range, version):
    """Perform a self-test on the device.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.
    memory_addr_range : dict
        The memory address range of the device.
    version : dict
        The version information of the device.
    """
    # Perform self-verify
    print("Performing self-test...")
    time_start = time.time()
    
    start_address = memory_addr_range['programFlashStart']
    end_address = memory_addr_range['programFlashEnd']
    total_length = end_address - start_address
    chunk_size = version['maxPacketLength'] - BASE_COMMAND_SIZE

    for address in range(start_address, end_address, chunk_size):
        response = self_verify(connection)
        
        if response['success'] != COMMAND_SUCCESS:
            raise Exception(f"Self-test failed at address {address:04X}")
        
        print_progress(
            address - start_address + chunk_size,
            total_length,
            time.time() - time_start,
        )
    print()
    print("Done")

def device_handshake(connection):
    """Perform a handshake with the device to get memory address range and version.

    Parameters
    ----------
    connection : serial.Serial
        The serial connection to the device.

    Returns
    -------
    tuple
        A tuple containing the memory address range and version information.
    """
    print("Connecting to device...")
    # Perform device handshake to get memory address range and version
    version = read_version(connection)
    memory_addr_range = get_memory_address_range(connection)
    
    print(f"Found Device ID: 0x{version['deviceId']:04X}")
    print(f"Boot Version: 0x{version['version']:04X}")
    print(f"App Start Address: 0x{memory_addr_range['programFlashStart']:08X}")
    print(f"App End Address: 0x{memory_addr_range['programFlashEnd']:08X}")
    print(f"Page Erase Size: {version['eraseSize']} bytes")
    print(f"Page Write Size: {version['writeSize']} bytes")
    print(f"Max Packet Length: {version['maxPacketLength']} bytes")
    return memory_addr_range, version

def main():
    """Main function to handle command-line arguments and perform actions accordingly."""
    parser = argparse.ArgumentParser(
        description='This tool is used to program the RDrive MCU with its embedded application.',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='Usage examples:\n'  
        './rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -f file.hex\n'
        './rdrive_bootflash.py -p /dev/ttyS0 -b 115200 -v\n'
        './rdrive_bootflash.py -p COM1 -b 115200 -e\n'        
    )
    parser.add_argument('-p', '--port', required=True, help='Serial port to use')
    parser.add_argument('-b', '--baudrate', type=int, required=True, help='Baudrate for serial communication')
    parser.add_argument('-f', '--flash', type=argparse.FileType('rb'), help='Hex file to flash the MCU')
    parser.add_argument('-r', '--reset', action='store_true', help='Reset')
    parser.add_argument('-c', '--checksum', action='store_true', help='Checksum the image after flashing')
    parser.add_argument('-t', '--self-test', action='store_true', help='Self test device')
    args = parser.parse_args()

    
    port = args.port
    baudrate = args.baudrate
    checksum = False
    # port = '/dev/ttyUSB0'
    # baudrate = 115200

    connection = serial.Serial(port, baudrate, timeout=SERIAL_TIMEOUT)
    memory_addr_range, version = device_handshake(connection)

    if args.flash:
        hexfile = args.flash.name  
        if args.checksum:
            checksum = True
        try:
            flash(connection, memory_addr_range, version, hexfile, checksum)
        finally:
            connection.close()
    elif args.reset:
        try:
            reset_device(connection)
        finally:
            connection.close()
    elif args.self_test:
        try:
            self_test(connection, memory_addr_range, version)
        finally:
            connection.close()
    else:
        connection.close()
        raise Exception("No valid command provided, see help for more information.")

if __name__ == '__main__':
    main()

