# Package

version = "0.1.0"
author = "Ryan Cotter"
description = "A debugger written in Nim"
license = "ISC"
srcDir = "src"
bin = @["tdbg"]

skipDirs = @["tests"]

# Dependencies

requires "nim >= 1.0.4"
requires "https://github.com/Tangdongle/ptrace.nim.git"

task run_tests, "Run our test suite":
  exec "nim c --out:tests/ptest tests/ptest.nim"
  exec "nim c --out:tests/tdbg src/tdbg.nim"
  exec "tests/tdbg -progName tests/ptest"
