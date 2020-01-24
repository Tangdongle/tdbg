## Main binary

import posix, linenoise, strutils, tables, typeinfo
import simple_parseopt, ptrace/ptrace

type
  Debugger = object
    progName: string
    pid: Pid
    breakpoints: Table[culong, Breakpoint]

  Breakpoint = object
    address: culong
    enabled: bool
    pid: Pid
    savedData: uint8

  InvalidRegisterNameException = object of Exception

let options = get_options:
  progName: string


proc `$`(r: Registers): string =
  ## Echoes all registers and their current values

  for name, val in r.fieldPairs:
    echo name, " = ", val.toHex


proc setRegisterVal(p: Pid, r: var Registers, regName: string,
    newVal: culong) =
  ## Sets a register of name `regName` to new value newVal

  # We use typeinfo to update a register by it's string name
  var anyR = r.toAny()
  for name in fields(anyR):
    if name.name == regName:
      echo "Found reg by name ", name.name
      echo "Current val is ", $name.any.getUint
      name.any.setBiggestUint(newVal)
    else:
      discard

  setRegs(p, addr r)


proc getRegisterVal(r: Registers, regName: string): uint64 =
  ## Finds a register of name regName and returns the value
  for name, val in r.fieldPairs:
    if name == regName:
      return val
  raise newException(InvalidRegisterNameException, "Could not find register " & regname)


proc getPCReg(d: Debugger): culong =
  ## Get the value of the PC register
  var regs: Registers
  getRegs(d.pid, addr regs)
  getRegisterVal(regs, "rip").culong


proc setPcReg(d: var Debugger, val: culong) =
  ## Set the value of the PC Register

  var regs: Registers
  getRegs(d.pid, addr regs)
  setRegisterVal(d.pid, regs, "rip", val)


proc initDebugger(progName: string, pid: Pid): Debugger =
  ## Create a new Debugger object
  result.progName = progName
  result.pid = pid
  result.breakpoints = initTable[culong, Breakpoint]()


func initBreakpoint(pid: Pid, address: culong): Breakpoint =
  ## Create a new Breakpont object
  result.pid = pid
  result.address = address
  result.enabled = false


proc enable(breakpoint: var Breakpoint) =
  ## Enable a breakpoint, replacing a portion of the executed code
  ## with a SIGTRAP call

  let data = getData(breakpoint.pid, breakpoint.address.clong)
  # Backup our data
  breakpoint.savedData = data.uint8 and 0xff

  # Interrupt is 0xcc
  let
    int3 = 0xcc
    dataWithInterrupt = ((data and (not 0xff)) or int3)

  # Insert our new data with an interrupt
  ptrace(PTRACE_POKEDATA, breakpoint.pid, breakpoint.address.clong, dataWithInterrupt)
  breakpoint.enabled = true


proc disable(breakpoint: var Breakpoint) =
  ## Disable a set breakpoint

  let
    data = getData(breakpoint.pid, breakpoint.address.clong)
    restoredData = ((data and (not 0xFF)).uint8 or breakpoint.savedData)

  ptrace(PTRACE_POKEDATA, breakpoint.pid, breakpoint.address.clong, restoredData)
  breakpoint.enabled = false


proc readMemory(debugger: Debugger, address: culong): string =
  ## Reads memory from a given address

  echo "Reading Memory from ", $address
  return getData(debugger.pid, address.clong).toHex


proc writeMemory(debugger: var Debugger, address: culong, value: uint64) =
  ## Write `value` as a given memory address `address`
  echo "Writing ", $value, " to ", $address
  ptrace(PTRACE_POKEDATA, debugger.pid, address.clong, value)


proc waitForSignal(d: Debugger) =
  ## wait for the next SIG sent to the child PID

  var
    waitStatus: cint
    options: cint = 0
  discard waitPid(d.pid, waitStatus, options)


proc stepOverBreakpoint(d: var Debugger) =
  ## Step over a breakpoint, executing a single instruction

  let bpLocation = d.getPCReg() - 1

  if bpLocation in d.breakpoints:
    var bp = d.breakpoints[bpLocation]

    if bp.enabled:
      let previousInstructionAddr = bpLocation
      d.setPcReg(previousInstructionAddr)

      bp.disable()
      singleStep(d.pid)
      d.waitForSignal()
      bp.enable()


proc setBreakpointAtAddress(debugger: var Debugger, address: culong) =
  ## Set a break point, saving the old stack and writing to it

  stderr.write("Set breakpoint at address 0x", address.toHex, "\n")
  var bp = initBreakpoint(debugger.pid, address)
  bp.enable()
  debugger.breakpoints[address] = bp


proc executeDebugee(progName: string) =
  ## Execute the target application with a trace

  traceMe()
  discard execl(progName, progName)


proc contExecution(debugger: var Debugger) =
  ## Continue execution and await the next SIGTRAP sent

  debugger.stepOverBreakpoint()

  cont(debugger.pid)

  waitForSignal(debugger)

func isPrefix(command: string, ofCommand: string): bool =
  ## Check if the command given is a prefix for a real command

  if command.len > ofCommand.len:
    result = false
  else:
    result = command[0 .. command.high] == ofCommand[0 .. command.high]


proc stripAddress(address: string): culong =
  ## Strips a 0x prefix from

  assert address.startsWith("0x")
  parseHexInt(address[2 .. address.high]).culong


proc handleCommand(debugger: var Debugger, line: string) =
  ## handles user command sent to the debugger
  let
    args = line.split(' ')
    command: string = $(args[0])

  if isPrefix(command, "continue"):
    ## Continues execution of the child program

    debugger.contExecution()
  elif isPrefix(command, "break"):
    ## Set a breakpoint

    let address = stripAddress(args[1])
    debugger.setBreakpointAtAddress(address)
  elif isPrefix(command, "register"):
    ## Register related commands

    var regs: Registers
    getRegs(debugger.pid, addr regs)
    if isPrefix(args[1], "dump"):
      # List all registers and their values

      echo $regs
    elif isPrefix(args[1], "read"):
      # Read a value from a register

      echo getRegisterVal(regs, args[2])
    elif isPrefix(args[1], "write"):
      # Write to a register

      let address = stripAddress(args[3]) # Strip 0x
      debugger.pid.setRegisterVal(regs, args[2], address)
      getRegs(debugger.pid, addr regs)
      echo "val after set is", getRegisterVal(regs, "ss")
      assert $getRegisterVal(regs, "ss") == args[2]
  elif isPrefix(command, "memory"):
    ## Memory commands

    let address = stripAddress(args[2]) # Strip 0x
    if isPrefix(args[1], "read"):
      echo debugger.readMemory(address)
    if isPrefix(args[1], "write"):
      let val = stripAddress(args[3])
      debugger.writeMemory(address, val)
  else:
    stderr.write("Unknown Command: ", command)


proc run(debugger: var Debugger) =
  ## Run the debugger

  var
    waitStatus: cint
    options: cint
  discard waitpid(debugger.pid, waitStatus, options)

  var line: cstring = readLine("minidbg> ".cstring)
  while line.len > 0:
    debugger.handleCommand($line)
    historyAdd(line)
    line = readLine("minidbg> ".cstring)


when isMainModule:
  var
    child: Pid

  child = fork()

  if child == 0:
    executeDebugee(options.progName)
  else:
    echo "initting debugger"
    var dbg = initDebugger(options.progName, child)
    dbg.run()
