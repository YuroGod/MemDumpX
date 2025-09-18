# MemDumpX
Lightweight IDA plugin for dumping in-memory decrypted binaries (PE, ELF) or arbitrary raw data to disk.

## Install
Save the plugin file (e.g. MemDumpX.py) into your IDA plugins directory:

- Windows example: `C:\Program Files\IDA\plugins\`

- Linux/macOS example: `/opt/ida/plugins/`

The plugin registers as MemDumpX with the default hotkey Ctrl-Alt-D.

## Usage
1. Open a database and navigate to the start address (or copy the VA where the file image begins).
2. Press the hotkey (Ctrl-Alt-D) or run the plugin from the Plugins menu.
3. Enter the start address (hex) when prompted (e.g. 0x10000000).
4. Choose dump mode(PE, ELF, RAW).
5. Save the file to disk.