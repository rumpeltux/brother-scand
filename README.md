# Brother scanner network driver

![Status](https://img.shields.io/badge/status-stable-green.svg)
[![License](https://img.shields.io/github/license/darsto/brother-scanner-driver.svg)](LICENSE.md)

Functional userspace driver for Brother scanners.

This is a server for brother click-to-scan feature.
To scan, simply press a button on the scanner.

This is a cross-platform, open-source and headless equivalent of Brother's Control Center 4.

Written in C11. Does not use any external dependencies.

## Advantages over the official Linux driver

Brother released a Linux driver for their scanners, however... 

The official Linux driver uses click-to-scan Brother protocol only to notify about the button press event.
After receiving such event, the driver closes the connection and starts up separate SANE application
that will establish connection with the same scanner (again!) and will request single page scan.

As for DCP-J105 scanner model, the connection establishment + handshake takes around 3 seconds.
To scan a single page, one would have to wait at least 6 seconds before the actual scanning starts.

The press-to-scan protocol offers much more than. It can be used to receive entire
image data within the same (original) connection. But only on Windows... Well, not anymore!

## Features

 * All the Windows Control Center 4 features, including:
   * Scan to IMAGE, OCR, EMAIL, FILE
   * Configurable scan params (DPI, Dimensions, Brightness, Contrast, Color, Compression)
   * Scan multiple pages with almost no interval (~ 0 sec)
   * Multiple scanners support
 * Password-protected hosts (a feature apparently not implemented in Control Center 4)
 * External scan hooks
 * Minimal resource usage when idle
 * Configurable hostname :)

## Installation
```
git clone https://github.com/rumpeltux/brother-scand.git
cd brother-scand
git submodule init
git submodule update
make && sudo make install
```

The driver **should** work for the most of Brother devices. 
However, it has only been tested on the DCP-J105, MFC-J430W, and HL-L2380DW.

If you have successfully run this driver with a different model,
please open a github issue and provide debug output logs if possible, so that
we can confirm behavior and add a testcase.

## Troubleshooting

* Use `build/brother-scan-cli -c your.config` to test your configuration
  without having to run the service.
* Add `-d` to your commandline (both for `build/brother-scan-cli` or in the
  `/etc/brother-scand/scanner.config` file) to collect debug output.
* Logs of the system service should be located in `/var/log/brother-scand.log`

## Running tests

Tests are written in C++ for convenience and use the GoogleTest framework.
The goal of those tests is to make sure the project keeps working even in the
absence of actual scanners to test with.

    sudo apt install cmake googletest
    make test

NOTE: Since tests rely on specific ports and their cleanup isn't always clean,
    running them repeatly may be flaky.
