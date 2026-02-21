# Function: IDA Plugin, to export specified function(s) code to file
#   supported export types: .c (pseudocode), .asm (assembly), .bin (binary)
# Author: CrifanLi
# Update: 20260221
# Usage:
#   IDA Pro -> File -> Script file ... -> Run this script: `idaExportFunctionCode.py`
#   -> got exported files in `exportedFunctionCode` subfolder

import idaapi
import idautils
import idc
import ida_hexrays
import ida_bytes
import ida_funcs
import ida_xref

import os
import re
import json
from datetime import datetime

################################################################################
# Config & Settings
################################################################################

VERSION = "20260221"

# config file path: same folder as this script
configFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def loadConfig(configPath):
  """Load config from json file

  Args:
    configPath: path to config.json
  Returns:
    dict: config dict
  """
  if not os.path.exists(configPath):
    print("[Error] Config file not found: %s" % configPath)
    return None

  with open(configPath, "r", encoding="utf-8") as f:
    configDict = json.load(f)

  # convert hex string address to int
  functionList = configDict.get("functionList", [])
  for funcConfig in functionList:
    for addrKey in ("startAddress", "endAddress"):
      addrVal = funcConfig.get(addrKey)
      if addrVal is not None:
        if isinstance(addrVal, str):
          funcConfig[addrKey] = int(addrVal, 16)

  return configDict

configDict = loadConfig(configFilePath)

isOverwrite = configDict.get("isOverwrite", True) if configDict else True
outputSubFolderName = configDict.get("outputSubFolderName", "exportedCode/function") if configDict else "exportedCode/function"
defaultExportTypes = configDict.get("defaultExportTypes", [".c", ".asm", ".bin"]) if configDict else [".c", ".asm", ".bin"]
functionList = configDict.get("functionList", []) if configDict else []

################################################################################
# Util Function
################################################################################

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
  """
  get current datetime then format to string

  eg:
      20171111_220722

  :param outputFormat: datetime output format
  :return: current datetime formatted string
  """
  curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
  curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
  return curDatetimeStr

def createFolder(folderFullPath):
  """
  create folder, even if already existed
  Note: for Python 3.2+
  """
  os.makedirs(folderFullPath, exist_ok=True)

################################################################################
# Export Logic
################################################################################

def exportPseudocode(ea, funcEndAddr, funcName):
  """Export function pseudocode (decompiled C code)

  Args:
    ea: function start address
    funcEndAddr: function end address (not used for decompile, but kept for consistency)
    funcName: function name
  Returns:
    str: pseudocode text, or None if failed
  """
  try:
    cfunc = ida_hexrays.decompile(ea)
    if cfunc:
      codeStr = "// Function: %s @ %s\n" % (funcName, hex(ea))
      codeStr += str(cfunc)
      return codeStr
    else:
      print("[Error] Could not decompile: %s @ %s" % (funcName, hex(ea)))
      return None
  except Exception as e:
    print("[Exception] Failed to decompile %s @ %s: %s" % (funcName, hex(ea), str(e)))
    return None

def getExternalXrefs(addr, curFuncStart, curFuncEnd):
  """Get meaningful CODE XREF (only from outside current function, or jump targets within)

  Args:
    addr: instruction address
    curFuncStart: current function start address
    curFuncEnd: current function end address
  Returns:
    list: list of xref info dicts
  """
  xrefs = list(idautils.XrefsTo(addr))
  if not xrefs:
    return []

  result = []
  for xref in xrefs:
    # only code xrefs: calls and jumps (exclude ordinary flow fl_F)
    if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN, ida_xref.fl_JF, ida_xref.fl_JN):
      continue

    fromAddr = xref.frm
    # skip if xref is from within current function (internal jump/branch)
    # but keep it if it's a call from outside
    isFromCurrentFunc = curFuncStart <= fromAddr < curFuncEnd
    isCall = xref.type in (ida_xref.fl_CF, ida_xref.fl_CN)
    isJump = xref.type in (ida_xref.fl_JF, ida_xref.fl_JN)

    # only keep: external calls, or external jumps
    if isFromCurrentFunc and not isCall:
      continue

    fromFunc = ida_funcs.get_func(fromAddr)
    if fromFunc:
      funcStart = fromFunc.start_ea
      funcNameStr = idaapi.get_func_name(funcStart) or ("sub_%X" % funcStart)
      offset = fromAddr - funcStart
      arrow = "↑" if fromAddr < addr else "↓"
      suffix = "p" if isCall else "j"
      result.append({
        "str": "%s+%X%s%s" % (funcNameStr, offset, arrow, suffix),
        "isCall": isCall,
        "isJump": isJump,
      })
    else:
      # no function - use segment:address format
      segName = getSegmentName(fromAddr)
      arrow = "↑" if fromAddr < addr else "↓"
      suffix = "p" if isCall else "j"
      result.append({
        "str": "%s:%016X%s%s" % (segName, fromAddr, arrow, suffix),
        "isCall": isCall,
        "isJump": isJump,
      })

  return result

def collectJumpTargets(ea, funcEndAddr):
  """Collect all jump target addresses within the function that need loc_xxx labels

  Args:
    ea: function start address
    funcEndAddr: function end address
  Returns:
    set: set of addresses that are jump targets
  """
  jumpTargets = set()
  curAddr = ea
  while curAddr < funcEndAddr:
    # check xrefs to this address
    for xref in idautils.XrefsTo(curAddr):
      # only jump xrefs (not calls, not flow)
      if xref.type in (ida_xref.fl_JF, ida_xref.fl_JN):
        fromAddr = xref.frm
        # only if jump is from within same function
        if ea <= fromAddr < funcEndAddr:
          jumpTargets.add(curAddr)
          break

    nextAddr = idc.next_head(curAddr, funcEndAddr)
    if nextAddr == idc.BADADDR or nextAddr <= curAddr:
      break
    curAddr = nextAddr

  return jumpTargets

def getFuncFrameInfo(ea):
  """Get function frame/stack variable info for IDA-style header

  Args:
    ea: function start address
  Returns:
    tuple: (attributes_str, var_lines_list)
  """
  func = ida_funcs.get_func(ea)
  if not func:
    return "", []

  # get attributes - use try/except for compatibility
  attrs = []
  flags = func.flags
  try:
    if flags & ida_funcs.FUNC_FRAME:
      attrs.append("bp-based frame")
  except AttributeError:
    pass
  try:
    if flags & ida_funcs.FUNC_NORET:
      attrs.append("noreturn")
  except AttributeError:
    pass
  try:
    if flags & ida_funcs.FUNC_THUNK:
      attrs.append("thunk")
  except AttributeError:
    pass

  attr_str = "; Attributes: " + ", ".join(attrs) if attrs else ""

  # get stack variables
  var_lines = []
  try:
    frame_id = idc.get_frame_id(ea)
    if frame_id is not None and frame_id != idc.BADADDR:
      frame_size = idc.get_struc_size(frame_id)
      # frsize = size of local variables area
      # saved registers start at offset frsize, so frame base is at frsize
      frame_base_offset = func.frsize
      seen_names = set()
      offset = 0
      while offset < frame_size:
        name = idc.get_member_name(frame_id, offset)
        if name and name not in seen_names:
          seen_names.add(name)
          if name.startswith("var_"):
            # try parse hex offset from name: var_10 -> 0x10
            try:
              var_offset = int(name[4:], 16)
              var_lines.append("%-20s =%s" % (name, formatVarOffset(var_offset, True)))
            except ValueError:
              # handle saved register naming: var_s0, var_s1, etc.
              # calculate offset relative to frame base
              rel_offset = offset - frame_base_offset
              if rel_offset >= 0:
                var_lines.append("%-20s =%s" % (name, formatVarOffset(rel_offset, False)))
              else:
                var_lines.append("%-20s =%s" % (name, formatVarOffset(-rel_offset, True)))
          elif name.startswith("arg_"):
            try:
              arg_offset = int(name[4:], 16)
              var_lines.append("%-20s =%s" % (name, formatVarOffset(arg_offset, False)))
            except ValueError:
              pass
        size = idc.get_member_size(frame_id, offset)
        if size is None or size <= 0:
          size = 1
        offset += size
  except Exception:
    pass

  return attr_str, var_lines

def formatVarOffset(val, isNegative):
  """Format variable offset value - no 0x prefix for values < 0x10
  
  Args:
    val: absolute offset value
    isNegative: True if offset is negative
  Returns:
    str: formatted offset string
  """
  if val < 0x10:
    if isNegative:
      return "-%d" % val
    else:
      return " %d" % val
  else:
    if isNegative:
      return "-0x%X" % val
    else:
      return " 0x%X" % val
  """Get segment name for an address

  Args:
    addr: address
  Returns:
    str: segment name like '.text' or 'seg000'
  """
  seg = idaapi.getseg(addr)
  if seg:
    name = idaapi.get_segm_name(seg)
    if name:
      return name
  return ".text"

def formatAddrWithSeg(addr):
  """Format address with segment prefix like IDA style: .text:00053C98

  Args:
    addr: address
  Returns:
    str: formatted address string
  """
  segName = getSegmentName(addr)
  return "%s:%08X" % (segName, addr)

def getFuncEntryXrefs(ea):
  """Get external xrefs to function entry (calls from other functions)

  Args:
    ea: function start address
  Returns:
    list: list of xref strings
  """
  xrefs = list(idautils.XrefsTo(ea))
  if not xrefs:
    return []

  result = []
  for xref in xrefs:
    # only call xrefs
    if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
      continue

    fromAddr = xref.frm
    fromFunc = ida_funcs.get_func(fromAddr)
    if fromFunc:
      funcStart = fromFunc.start_ea
      funcNameStr = idaapi.get_func_name(funcStart) or ("sub_%X" % funcStart)
      offset = fromAddr - funcStart
      arrow = "↑" if fromAddr < ea else "↓"
      result.append("%s+%X%sp" % (funcNameStr, offset, arrow))
    else:
      # no function - use segment:address format
      segName = getSegmentName(fromAddr)
      arrow = "↑" if fromAddr < ea else "↓"
      result.append("%s:%016X%sp" % (segName, fromAddr, arrow))

  return result

def getFuncTypeStr(ea):
  """Get function type/prototype string
  
  Args:
    ea: function start address
  Returns:
    str: function type string like "__int64 sub_XXX(__int64, __int64, ...)" or None
  """
  try:
    tinfo = idaapi.tinfo_t()
    if idaapi.get_tinfo(tinfo, ea):
      funcType = str(tinfo)
      if funcType:
        return funcType
  except:
    pass
  return None

def exportAssembly(ea, funcEndAddr, funcName):
  """Export function assembly code in IDA-style format

  Args:
    ea: function start address
    funcEndAddr: function end address
    funcName: function name
  Returns:
    str: assembly text, or None if failed
  """
  asmLines = []
  segName = getSegmentName(ea)
  addrFmt = "%s:%016X" % (segName, ea)

  # 1. header line
  asmLines.append("%s ; =============== S U B R O U T I N E =======================================" % addrFmt)
  asmLines.append(addrFmt)

  # 2. Attributes (or extra blank line if no attributes)
  attr_str, var_lines = getFuncFrameInfo(ea)
  if attr_str:
    asmLines.append("%s %s" % (addrFmt, attr_str))
    asmLines.append(addrFmt)
  else:
    # extra blank line when no attributes
    asmLines.append(addrFmt)

  # 3. function prototype with function name
  funcTypeStr = getFuncTypeStr(ea)
  if funcTypeStr:
    # insert function name into prototype: __int64(__int64, ...) -> __int64 funcName(__int64, ...)
    if '(' in funcTypeStr:
      retType = funcTypeStr.split('(')[0].strip()
      params = funcTypeStr.split('(')[1].rstrip(')')
      asmLines.append("%s ; %s %s(%s)" % (addrFmt, retType, funcName, params))
    else:
      asmLines.append("%s ; %s" % (addrFmt, funcTypeStr))

  # 4. function name label with CODE XREF
  entryXrefs = getFuncEntryXrefs(ea)
  if entryXrefs:
    asmLines.append("%s %-40s ; CODE XREF: %s" % (addrFmt, funcName, entryXrefs[0]))
    # additional xrefs on separate lines
    for xref in entryXrefs[1:4]:  # show up to 3 more
      asmLines.append("%s %s ; %s" % (addrFmt, " "*40, xref))
    if len(entryXrefs) > 4:
      asmLines.append("%s %s ; ..." % (addrFmt, " "*40))
  else:
    asmLines.append("%s %s" % (addrFmt, funcName))
  asmLines.append(addrFmt)

  # 5. var definitions
  for vl in var_lines:
    asmLines.append("%s %s" % (addrFmt, vl))
  if var_lines:
    asmLines.append(addrFmt)

  # 6. __unwind marker
  asmLines.append("%s ; __unwind {" % addrFmt)

  # collect jump targets for loc_xxx labels
  jumpTargets = collectJumpTargets(ea, funcEndAddr)

  curAddr = ea
  lastAddr = ea
  prevMnemonic = ""  # track previous instruction mnemonic
  while curAddr < funcEndAddr:
    lastAddr = curAddr
    addrPrefix = "%s:%016X" % (segName, curAddr)

    # add loc_xxx label if this is a jump target (not function entry)
    if curAddr in jumpTargets and curAddr != ea:
      # add separator line after control flow terminating instructions (RET, B, etc.)
      if prevMnemonic.upper() in ("RET", "B", "BR", "BX", "JMP", "RETAB", "RETAA"):
        asmLines.append("%s ; ---------------------------------------------------------------------------" % addrPrefix)
      asmLines.append(addrPrefix)
      locLabel = idc.get_name(curAddr) or ("loc_%X" % curAddr)
      # for loc labels, show internal jump xrefs
      internalJumpXrefs = []
      for xref in idautils.XrefsTo(curAddr):
        if xref.type in (ida_xref.fl_JF, ida_xref.fl_JN):
          fromAddr = xref.frm
          if ea <= fromAddr < funcEndAddr:
            offset = fromAddr - ea
            arrow = "↑" if fromAddr < curAddr else "↓"
            internalJumpXrefs.append("%s+%X%sj" % (funcName, offset, arrow))

      if internalJumpXrefs:
        if len(internalJumpXrefs) == 1:
          asmLines.append("%s %-40s ; CODE XREF: %s" % (addrPrefix, locLabel, internalJumpXrefs[0]))
        else:
          asmLines.append("%s %-40s ; CODE XREF: %s ..." % (addrPrefix, locLabel, internalJumpXrefs[0]))
      else:
        asmLines.append("%s %s" % (addrPrefix, locLabel))

    # get meaningful external xrefs for this instruction (skip first instruction - xrefs shown in header)
    xrefComment = ""
    if curAddr != ea:
      xrefInfos = getExternalXrefs(curAddr, ea, funcEndAddr)
      if xrefInfos:
        xrefStrs = [x["str"] for x in xrefInfos]
        if len(xrefStrs) == 1:
          xrefComment = "; CODE XREF: %s" % xrefStrs[0]
        else:
          xrefComment = "; CODE XREF: %s ..." % xrefStrs[0]

    # get disassembly line
    disasmLine = idc.generate_disasm_line(curAddr, 0)
    if disasmLine:
      if xrefComment:
        asmLines.append("%s                 %-40s %s" % (addrPrefix, disasmLine, xrefComment))
      else:
        asmLines.append("%s                 %s" % (addrPrefix, disasmLine))
      
      # for call instructions, get callee's repeatable comment and add as continuation lines
      mnemonic = idc.print_insn_mnem(curAddr) or ""
      if mnemonic.upper() in ("BL", "BLR", "CALL", "BLX"):
        # get call target address
        callTarget = idc.get_operand_value(curAddr, 0)
        if callTarget != idc.BADADDR:
          # get repeatable comment of the called function
          repeatCmt = idc.get_func_cmt(callTarget, 1)  # 1 = repeatable
          if repeatCmt:
            # split into lines - skip first line as it's already in disasm output
            cmtLines = repeatCmt.split('\n')
            for cmtLine in cmtLines[1:]:  # skip first line
              # preserve empty lines as "; " only
              if cmtLine.strip():
                asmLines.append("%s                                         ; %s" % (addrPrefix, cmtLine))
              else:
                asmLines.append("%s                                         ;" % addrPrefix)
    else:
      asmLines.append("%s ; [Error] Could not disassemble" % addrPrefix)

    # update previous mnemonic for next iteration
    prevMnemonic = idc.print_insn_mnem(curAddr) or ""

    # move to next instruction
    nextAddr = idc.next_head(curAddr, funcEndAddr)
    if nextAddr == idc.BADADDR or nextAddr <= curAddr:
      break
    curAddr = nextAddr

  # end marker at last instruction address
  asmLines.append("%s:%016X ; } // starts at %X" % (segName, lastAddr, ea))
  asmLines.append("%s:%016X ; End of function %s" % (segName, lastAddr, funcName))

  return "\n".join(asmLines)

def exportBinary(ea, funcEndAddr, funcName):
  """Export function binary data

  Args:
    ea: function start address
    funcEndAddr: function end address
    funcName: function name
  Returns:
    bytes: binary data, or None if failed
  """
  size = funcEndAddr - ea
  if size <= 0:
    print("[Error] Invalid size %d for %s @ %s" % (size, funcName, hex(ea)))
    return None

  binData = ida_bytes.get_bytes(ea, size)
  if binData is None:
    print("[Error] Could not read %d bytes for %s @ %s" % (size, funcName, hex(ea)))
    return None

  return binData

def writeToFile(outputFullPath, content, isBinary=False):
  """Write content to file

  Args:
    outputFullPath: full path to output file
    content: text string or bytes data
    isBinary: True for binary mode
  Returns:
    bool: True if success
  """
  if not isOverwrite and os.path.exists(outputFullPath):
    print("  Skip (already exists): %s" % outputFullPath)
    return False

  if isBinary:
    with open(outputFullPath, "wb") as f:
      f.write(content)
  else:
    with open(outputFullPath, "w", encoding="utf-8") as f:
      f.write(content)

  return True

def getFuncEndAddress(ea, configEndAddr=None):
  """Get function end address

  Args:
    ea: function start address
    configEndAddr: optional end address from config
  Returns:
    int: function end address, or None if failed
  """
  if configEndAddr:
    return configEndAddr

  func = ida_funcs.get_func(ea)
  if func:
    return func.end_ea

  # for loc_xxx or other non-function labels: try find next head/function as boundary
  nextFunc = idc.get_next_func(ea)
  if nextFunc != idc.BADADDR:
    return nextFunc

  print("[Error] Cannot determine end address for %s, please specify endAddress in config" % hex(ea))
  return None

def getFuncName(ea, configFuncName=None):
  """Get function/label name

  Args:
    ea: function start address
    configFuncName: optional name from config
  Returns:
    str: function name
  """
  if configFuncName:
    return configFuncName

  # try function name first (for sub_xxx)
  funcName = idaapi.get_func_name(ea)
  if funcName:
    return funcName

  # try any name at address (for loc_xxx, etc.)
  labelName = idc.get_name(ea)
  if labelName:
    return labelName

  # fallback: use address as name
  return "func_%X" % ea

def parseAddressFromFuncName(funcName):
  """Parse start address from funcName with pattern: xxx_<hexAddress>

  eg: vmGetHandler_31BA0 -> 0x31BA0
      sub_A389 -> 0xA389
      loc_31D38 -> 0x31D38

  Args:
    funcName: function name string
  Returns:
    int: parsed address, or None if failed
  """
  match = re.match(r'^.+_([0-9A-Fa-f]+)$', funcName)
  if match:
    addrStr = match.group(1)
    try:
      return int(addrStr, 16)
    except ValueError:
      pass
  return None

def processSingleFunction(funcConfig, outputFolder):
  """Process one function config and export

  Args:
    funcConfig: dict with startAddress, endAddress, funcName, exportTypes
    outputFolder: output folder path
  Returns:
    dict: result info
  """
  startAddress = funcConfig.get("startAddress")
  configEndAddr = funcConfig.get("endAddress", None)
  configFuncName = funcConfig.get("funcName", None)
  exportTypes = funcConfig.get("exportTypes", defaultExportTypes)

  # resolve startAddress: either from config directly, or parsed from funcName
  if startAddress is None:
    if configFuncName:
      startAddress = parseAddressFromFuncName(configFuncName)
      if startAddress is None:
        print("[Error] Cannot parse address from funcName '%s', expected pattern: xxx_<hexAddress>" % configFuncName)
        return {"ok": False, "error": "Cannot parse address from funcName"}
    else:
      print("[Error] Missing both startAddress and funcName in config")
      return {"ok": False, "error": "Missing startAddress and funcName"}

  if not exportTypes:
    print("[Error] Missing exportTypes for address %s" % hex(startAddress))
    return {"ok": False, "error": "Missing exportTypes"}

  # resolve function info
  funcName = getFuncName(startAddress, configFuncName)
  funcEndAddr = getFuncEndAddress(startAddress, configEndAddr)

  if funcEndAddr is None:
    return {"ok": False, "error": "Cannot determine function end"}

  print("Processing: %s @ %s - %s" % (funcName, hex(startAddress), hex(funcEndAddr)))

  result = {
    "ok": True,
    "funcName": funcName,
    "startAddress": hex(startAddress),
    "endAddress": hex(funcEndAddr),
    "exported": [],
    "failed": [],
  }

  # generate base filename
  # if funcName already contains address suffix (like vmGetHandler_31BA0), use it directly
  # otherwise append _<address>
  if parseAddressFromFuncName(funcName) is not None:
    baseFilename = funcName
  else:
    baseFilename = "%s_%X" % (funcName, startAddress)

  for exportType in exportTypes:
    exportType = exportType.lower()
    outputFilename = "%s%s" % (baseFilename, exportType)
    outputFullPath = os.path.join(outputFolder, outputFilename)

    print("  Exporting %s -> %s" % (exportType, outputFilename))

    exportOk = False

    if exportType == ".c":
      content = exportPseudocode(startAddress, funcEndAddr, funcName)
      if content:
        exportOk = writeToFile(outputFullPath, content, isBinary=False)

    elif exportType == ".asm":
      content = exportAssembly(startAddress, funcEndAddr, funcName)
      if content:
        exportOk = writeToFile(outputFullPath, content, isBinary=False)

    elif exportType == ".bin":
      content = exportBinary(startAddress, funcEndAddr, funcName)
      if content:
        exportOk = writeToFile(outputFullPath, content, isBinary=True)

    else:
      print("  [Error] Unsupported export type: %s" % exportType)

    if exportOk:
      result["exported"].append(exportType)
      print("  Exported: %s" % outputFullPath)
    else:
      result["failed"].append(exportType)

  return result

################################################################################
# Main
################################################################################

def main():
  # print banner
  print("="*60)
  print(" idaExportFunctionCode v%s" % VERSION)
  print("="*60)
  print("")

  curDatetimeStr = getCurDatetimeStr()
  print("curDatetimeStr=%s" % curDatetimeStr)

  if not functionList:
    print("[Error] functionList is empty, please config functions to export")
    return

  # 1. wait for IDA auto-analysis to finish
  print("Waiting for auto-analysis to finish...")
  idaapi.auto_wait()

  # 2. check Hex-Rays decompiler availability (only if any function needs .c export)
  needDecompile = any(
    ".c" in [t.lower() for t in fc.get("exportTypes", defaultExportTypes)]
    for fc in functionList
  )
  if needDecompile:
    if not ida_hexrays.init_hexrays_plugin():
      print("[Error] Hex-Rays decompiler is not available. Cannot export .c pseudocode.")
      # still continue for .asm and .bin exports

  # 3. setup output folder
  inputFileFullPath = idaapi.get_input_file_path()
  print("inputFileFullPath=%s" % inputFileFullPath)
  inputFilename = os.path.basename(inputFileFullPath)
  inputPath = os.path.dirname(inputFileFullPath)
  print("inputFilename=%s" % inputFilename)

  outputSubFolder = os.path.join(inputPath, outputSubFolderName)
  print("outputSubFolder=%s" % outputSubFolder)
  createFolder(outputSubFolder)

  # 4. process each function
  print("="*60)
  print("Start exporting %d function(s)..." % len(functionList))
  print("="*60)

  allResults = []
  okCount = 0
  failCount = 0

  for idx, funcConfig in enumerate(functionList):
    print("")
    print("-"*40)
    print("[%d/%d] Processing function..." % (idx + 1, len(functionList)))
    print("-"*40)

    result = processSingleFunction(funcConfig, outputSubFolder)
    allResults.append(result)

    if result.get("ok"):
      okCount += 1
    else:
      failCount += 1

  # 5. summary
  print("")
  print("="*60)
  print("Export Summary")
  print("="*60)
  print("Total functions: %d" % len(functionList))
  print("  OK: %d" % okCount)
  print("  Fail: %d" % failCount)
  print("Output folder: %s" % outputSubFolder)

  for r in allResults:
    if r.get("funcName"):
      exportedStr = ", ".join(r.get("exported", []))
      failedStr = ", ".join(r.get("failed", []))
      print("  %s @ %s: exported=[%s] failed=[%s]" % (
        r["funcName"], r.get("startAddress", "?"), exportedStr, failedStr))

  print("="*60)
  print("Done!")

if __name__ == "__main__":
  main()
