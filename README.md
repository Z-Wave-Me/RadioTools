# Transmission Utility

This utility is used to broadcast Z-Wave packets from one segment to another via the Web Serial service. It allows you to combine several sections of the same network that are far apart from each other or even using different Z-Wave regions. Z-Wave.Me radio modules such as [Z-Station](https://z-wave.me/products/z-station/), [mPCIe](https://z-wave.me/products/mpcie/), [RaZberry](https://z-wave.me/products/razberry/), [Z-Uno](https://z-uno.z-wave.me/) usis required (you need to purchase a special license).

Usage:

    python3 zme_transmission.py svc -c transmission.json

# Web Serial

The service is used to access the serial ports of the computer via Web sockets.

Typical usage:

    python3 zme_webserial.py svc

# External python packages installation

    python3 -m pip install pyserial asyncio intelhex websockets pycryptodome colorama requests

# Logs

By default logs are placed into ~/ZMEStorage directory.
This can be changed by setting ZME\_LOGPATH environment variable.
