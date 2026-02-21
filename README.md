# idaExportFunctionCode

* Update: `20260221`

## Function

IDA Plugin, to export specified function(s) code to file

Supported address types:

* `sub_xxx` : function entry point
* `loc_xxx` : code label (non-function address)

Supported export types:

* `.c` : pseudocode (decompiled C code, via Hex-Rays)
* `.asm` : assembly code (IDA-style format with XREF, loc labels)
* `.bin` : binary code (raw bytes)

## Git Repo

https://github.com/crifan/idaExportFunctionCode

https://github.com/crifan/idaExportFunctionCode.git

## Usage

### 1. Config

Edit `config.json` (same folder as the script):

```json
{
  "isOverwrite": true,
  "outputSubFolderName": "exportedCode/function",
  "defaultExportTypes": [".c", ".asm", ".bin"],
  "functionList": [
    {
      "startAddress": "0xA389"
    },
    {
      "funcName": "vmGetHandler_31BA0"
    },
    {
      "startAddress": "0x31D38",
      "endAddress": "0x31D40",
      "exportTypes": [".asm", ".bin"]
    },
    {
      "startAddress": "0xB000",
      "endAddress": "0xB100",
      "funcName": "myFunc",
      "exportTypes": [".c"]
    }
  ]
}
```

Parameters:

* Global
  * `isOverwrite` : overwrite output file if already existed. Default: `true`
  * `outputSubFolderName` : output subfolder name. Default: `"exportedCode/function"`
  * `defaultExportTypes` : default export types for all functions. Default: `[".c", ".asm", ".bin"]`
* Per function (in `functionList` array)
  * `startAddress` and `funcName` : at least one is required
    * `startAddress` : hex string, eg: `"0xA389"`
    * `funcName` : function name, eg: `"sub_A389"`, `"vmGetHandler_31BA0"`. If omitted, auto get from IDA
    * If only `funcName` is provided (without `startAddress`), the address is parsed from the `xxx_<hexAddress>` suffix, eg: `"vmGetHandler_31BA0"` -> address `0x31BA0`
  * `endAddress` : (optional) end address. If omitted, auto detect from IDA. **Note**: for `loc_xxx` addresses, it is recommended to specify `endAddress` explicitly
  * `exportTypes` : (optional) list of export types, supported: `".c"`, `".asm"`, `".bin"`. If omitted, use `defaultExportTypes`

### 2. Run

`IDA Pro` -> `File` -> `Script file ...` -> (Double click to ) Run this script: `idaExportFunctionCode.py`

### 3. Output

Exported files in subfolder `exportedCode/function/` (same directory as input binary), eg:

```
exportedCode/function/
  sub_A389.c
  sub_A389.asm
  sub_A389.bin
  vmGetHandler_31BA0.c
  vmGetHandler_31BA0.asm
  vmGetHandler_31BA0.bin
  loc_31D38.asm
  loc_31D38.bin
  myFunc_B000.c
```

## Example

### Export pseudocode (.c)

```c
// Function: sub_A389 @ 0xa389
int __fastcall sub_A389(int a1, int a2)
{
  ...
}
```

### Export assembly (.asm)

IDA-style format with 16-digit segment:address, CODE XREF, function prototype, and loc labels:

```asm
__TEXT:000000000000A389 ; =============== S U B R O U T I N E =======================================
__TEXT:000000000000A389
__TEXT:000000000000A389 ; Attributes: bp-based frame
__TEXT:000000000000A389
__TEXT:000000000000A389 ; __int64 sub_A389(__int64, __int64)
__TEXT:000000000000A389 sub_A389                                 ; CODE XREF: main+20↑p
__TEXT:000000000000A389
__TEXT:000000000000A389 var_10               =-0x10
__TEXT:000000000000A389 arg_0                = 0
__TEXT:000000000000A389
__TEXT:000000000000A389 ; __unwind {
__TEXT:000000000000A389                 STP  X29, X30, [SP,#-0x10+var_10]!
__TEXT:000000000000A38D                 MOV  X29, SP
__TEXT:000000000000A391                 B.EQ loc_A3A0
...
__TEXT:000000000000A39C                 RET
__TEXT:000000000000A3A0 ; ---------------------------------------------------------------------------
__TEXT:000000000000A3A0
__TEXT:000000000000A3A0 loc_A3A0                                 ; CODE XREF: sub_A389+8↑j
__TEXT:000000000000A3A0                 MOV  W0, #1
...
__TEXT:000000000000A3C9 ; } // starts at A389
__TEXT:000000000000A3C9 ; End of function sub_A389
```

Features:
* 16-digit address format (`segment:0000000000XXXXXX`)
* Function prototype comment (from IDA type info)
* Variable definitions with formatted offsets
* `; __unwind {` / `; }` block markers
* Separator lines (`; ---...`) after control flow instructions (RET, B, BR, JMP)
* Arrow indicators: `↑` (xref from lower address), `↓` (xref from higher address)
* Suffix indicators: `p` (call/procedure), `j` (jump)

### Export binary (.bin)

Raw binary data of the function bytes.
