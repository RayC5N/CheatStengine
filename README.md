# Cheat Stengine

<p align="center">
    <img src="Images/128x128.png" width="128"/>
</p>

Cheat Stengine is a reverse engineering tool for Windows processes.
The goal is to create a tool that has a better user experience than Cheat Engine, while still providing powerful
features for reverse engineering, debugging, memory analysis, and game hacking.

> [!WARNING]
> Cheat Stengine is still in the very early stages of development. Many features are not yet implemented, and the tool
> may be unstable. Expect bugs, crashes, and breaking changes between versions.

> [!NOTE]
> If you're on an AMD chipset, you might face some issues. If you do, please copy the generated dump file and create an issue
> with any relevant information that could help us identify the issue.
>
> When using the Kernel mode we are not responsible for individual data loss, system instability, or other issues caused by using Cheat Stengine.
> Use it at your own risk.

## Preview

<p align="center">
    <img src="https://raw.githubusercontent.com/sten-code/CheatStengine/master/Images/preview.png" width="900"/>
</p>

## Compiling from Source

```bash
cmake -S . -B build
cmake --build build --config Release
```

## Features

* [x] Pattern Scanner
* [x] MCP Support
* [x] Disassembler
* [x] Assembler
* [x] Struct Dissector
* [x] Memory Scanner
* [x] Address Watcher
* [x] Module List
* [x] PE Viewer
* [x] Kernel Mode
* [x] Pattern Generator
* [ ] Process Dumper
* [ ] String Scanner/Viewer
* [ ] Code Cave Scanner
* [ ] Code Injection
* [ ] Syscall Tracer
* [ ] Lua Scripting
* [ ] Pointer Scanner
* [ ] Memory Viewer
* [ ] Debugger
* [ ] Thread Explorer
* [ ] Handle Viewer
* [ ] Plugin System
* [ ] DBVM

Bug reports and contributions are welcome. If you encounter a crash, please include relevant logs or dump files when
creating an issue.
