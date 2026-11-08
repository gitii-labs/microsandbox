"""Check the declared libclang by parsing real standard C and Ruby headers."""

import ctypes
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


class CXString(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("flags", ctypes.c_uint)]


library_dir = Path(os.environ["LIBCLANG_PATH"])
library = library_dir / ("libclang.dylib" if os.uname().sysname == "Darwin" else "libclang.so")
clang = ctypes.CDLL(str(library))
clang.clang_getClangVersion.restype = CXString
clang.clang_getCString.argtypes = [CXString]
clang.clang_getCString.restype = ctypes.c_char_p
clang.clang_disposeString.argtypes = [CXString]


def text(value):
    result = clang.clang_getCString(value).decode()
    clang.clang_disposeString(value)
    return result


version = text(clang.clang_getClangVersion())
assert "23.1.5" in version, version
print(f"Library: {library.resolve()}")
print(f"Version: {version}")

ruby = json.loads(subprocess.check_output([
    "ruby", "-rjson", "-rrbconfig", "-e",
    'puts JSON.generate(RbConfig::CONFIG.values_at("rubyhdrdir", "rubyarchhdrdir"))',
], text=True))
compiler = subprocess.run(
    ["gcc", "-E", "-x", "c", "-", "-v"], input="", text=True,
    capture_output=True, check=True,
)
include_search = compiler.stderr.split("#include <...> search starts here:\n", 1)[1]
includes = [line.strip() for line in include_search.split("End of search list.", 1)[0].splitlines()]
flags = ["-x", "c", "-std=gnu11"]
flags += [f"-I{path}" for path in ruby]
flags += [f"-isystem{path}" for path in includes]
flags += shlex.split(os.environ["BINDGEN_EXTRA_CLANG_ARGS"])
args = (ctypes.c_char_p * len(flags))(*(flag.encode() for flag in flags))

clang.clang_createIndex.argtypes = [ctypes.c_int, ctypes.c_int]
clang.clang_createIndex.restype = ctypes.c_void_p
clang.clang_parseTranslationUnit.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int,
    ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
]
clang.clang_parseTranslationUnit.restype = ctypes.c_void_p
clang.clang_getNumDiagnostics.argtypes = [ctypes.c_void_p]
clang.clang_getNumDiagnostics.restype = ctypes.c_uint
clang.clang_getDiagnostic.argtypes = [ctypes.c_void_p, ctypes.c_uint]
clang.clang_getDiagnostic.restype = ctypes.c_void_p
clang.clang_getDiagnosticSeverity.argtypes = [ctypes.c_void_p]
clang.clang_getDiagnosticSeverity.restype = ctypes.c_uint
clang.clang_getDiagnosticSpelling.argtypes = [ctypes.c_void_p]
clang.clang_getDiagnosticSpelling.restype = CXString
clang.clang_disposeDiagnostic.argtypes = [ctypes.c_void_p]
clang.clang_disposeTranslationUnit.argtypes = [ctypes.c_void_p]
clang.clang_disposeIndex.argtypes = [ctypes.c_void_p]

index = clang.clang_createIndex(0, 0)
with tempfile.TemporaryDirectory() as directory:
    header = Path(directory) / "probe.h"
    header.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n#include <ruby.h>\n"
        "struct libclang_probe { size_t length; uint64_t number; VALUE ruby_value; };\n"
    )
    unit = clang.clang_parseTranslationUnit(index, os.fsencode(header), args, len(flags), None, 0, 0)
    assert unit, "libclang did not produce a translation unit"
    errors = []
    for number in range(clang.clang_getNumDiagnostics(unit)):
        diagnostic = clang.clang_getDiagnostic(unit, number)
        if clang.clang_getDiagnosticSeverity(diagnostic) >= 3:
            errors.append(text(clang.clang_getDiagnosticSpelling(diagnostic)))
        clang.clang_disposeDiagnostic(diagnostic)
    clang.clang_disposeTranslationUnit(unit)
    assert not errors, errors
clang.clang_disposeIndex(index)
print(f"Parsed stddef.h, stdint.h and ruby.h successfully: {ruby}")
