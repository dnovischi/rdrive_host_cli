# RDrive Bootloader Host CLI

This tool is used to program the RDrive MCU with its embedded application. If you are looking for a general tool for  PIC24 and dsPIC33, consider using [mcbootflash](https://github.com/bessman/mcbootflash).

## Installation

1. Clone the repository:

    ```sh
    git clone <repository_url>
    cd <repository_directory>
    ```

2. Create a virtual environment (optional but recommended):

    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required dependencies:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

The script provides several functionalities including flashing a HEX file, resetting the device, and performing a self-test. Below are the usage examples:

### Flashing a HEX File

To flash a HEX file to the MCU:

```sh
./rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -f file.hex
```

### Resetting the Device

To reset the device:

```sh
./rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -r
```

### Performing a Self-Test

To perform a self-test on the device:

```sh
./rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -t
```

### Verifying the Checksum After Flashing

To verify the checksum after flashing a HEX file:

```sh
./rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -f file.hex -c
```

### Command-Line Arguments

- `-p`, `--port`: Serial port to use (required).
- `-b`, `--baudrate`: Baudrate for serial communication (required).
- `-f`, `--flash`: Hex file to flash the MCU.
- `-r`, `--reset`: Reset the device.
- `-c`, `--checksum`: Checksum after flashing.
- `-t`, `--self-test`: Perform a self-test on the device.

## Example Usage

```sh
./rdrive_bootflash.py -p /dev/ttyUSB0 -b 115200 -f rdrive-bootapp-boilerplate.X.production.hex -c
```

This command will flash the `rdrive-bootapp-boilerplate.X.production.hex` file to the MCU connected to `/dev/ttyUSB0` at a baudrate of 115200 and verify the checksum after flashing.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.