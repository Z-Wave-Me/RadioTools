# Transmission Utility

This utility is used to broadcast Z-Wave packets from one segment to another via the Web Serial service. It allows you to combine several sections of the same network that are far apart from each other or even using different Z-Wave regions. Z-Wave.Me radio modules such as [Z-Station](https://z-wave.me/products/z-station/), [mPCIe](https://z-wave.me/products/mpcie/), [RaZberry](https://z-wave.me/products/razberry/), [Z-Uno](https://z-uno.z-wave.me/) usis required (you need to purchase a special license).

Usage:

    python3 zme_transmission.py svc -c transmission.json

# Web Serial

The service is used to access the serial ports of the computer via Web sockets.

Typical usage:

    python3 zme_webserial.py svc

# Dependencies installation

    python3 -m pip install pyserial asyncio intelhex websockets pycryptodome colorama requests

# Logs

By default logs are placed into ~/ZMEStorage directory.
This can be changed by setting ZME\_LOGPATH environment variable.

# Install scripts as services

To install scripts as system services run `make install` and follow the
instructions in the command output. This command will install all scripts
to /opt/zme_radiotools, a crontab file (in /etc/cron.d/) and init.d script
(in /etc/init.d/). Init.d script starts scripts according to a conf
file - /opt/zme_radiotools/zme_radiotools.conf. Every enabled script will be started.

# Note

zme_webserial.py on SIGTERM is output in the log the next lines:

```
ERROR    [2024-07-29 14:02:08,464]  _scanPorts:Traceback (most recent call last):
  File "/opt/zme_radiotools/zme_webserial.py", line 135, in _scanPorts
    await asyncio.sleep(1.0)
  File "/usr/lib/python3.9/asyncio/tasks.py", line 654, in sleep
    return await future
asyncio.exceptions.CancelledError
```

This is a normal behaviour at current time.
