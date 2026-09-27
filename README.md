# TraceClean

A lightweight Windows Event Log cleaning utility built in C++.

TraceClean allows you to search and remove specific Windows Event Log entries by Event ID or message content. It works directly with Windows Event Log files and is designed for fast, simple operation.

## Features

- Clean specific Event IDs
- Search and remove events by message text
- Supports:
  - System
  - Application
  - Sysmon Operational
- Direct EVTX processing
- Administrator privilege support
- Lightweight native Windows executable
- x64 build
- C++17
- Minimal dependencies

## Requirements

- Windows 10 / Windows 11
- Administrator privileges
- x64 system

## Build

Built using:

- C++17
- MinGW-w64 GCC
- Windows Event Log API

Required libraries:

```text
wevtapi
advapi32
ole32
