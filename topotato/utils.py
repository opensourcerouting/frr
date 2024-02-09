#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2022  David Lamparter for NetDEF, Inc.
"""
Random utility functions for use in topotato.
"""

# TODO: this needs another round of cleanup, and JSONCompare split off.

import sys
import os
import re
import logging
import traceback
import atexit
import shlex
import fcntl
import json
import difflib

from typing import Any, Dict, List, Union

from .defer import subprocess
from .exceptions import TopotatoCLICompareFail

logger = logging.getLogger("topotato")

_wsp_re = re.compile(r"^[ \t]+")


def deindent(text: str, trim=False) -> str:
    """
    Determine and strip common indentation from a string.

    Intended for use with docstrings, which would generally be indented to
    match the surrounding code.  Common indentation is determined by finding
    the longest common prefix for all lines that contain any non-whitespace
    characters, i.e. whitespace-only lines are ignored.  (Those shouldn't have
    any indentation anyway.)
    """
    text = text.lstrip("\n")
    lines = text.split("\n")
    common_prefix = None
    for line in lines:
        if line.strip() == "":
            continue
        if m := _wsp_re.match(line):
            this_prefix = m.group(0)
            if common_prefix is None:
                common_prefix = this_prefix
                continue

            this_prefix = this_prefix[: len(common_prefix)]
            while this_prefix != common_prefix:
                common_prefix = common_prefix[:-1]
                this_prefix = this_prefix[: len(common_prefix)]
        else:
            common_prefix = None
            break

    if common_prefix is None:
        return text

    do_trim = (lambda s: s.rstrip(" \t")) if trim else (lambda s: s)
    return "\n".join(do_trim(line)[len(common_prefix) :] for line in lines)


def get_textdiff(text1: str, text2: str, title1="", title2="", **opts) -> str:
    """
    Diff formatting wrapper (just cleans up line endings)

    :param opts:  Remaining keywords passed to :py:func:`difflib.unified_diff`.
    :return:  Formatted diff, empty string if text1 == text2.
    """

    diff = "\n".join(
        difflib.unified_diff(text1, text2, fromfile=title1, tofile=title2, **opts)
    )
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff


class JSONCompareResult:
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error, d1=None, d2=None):
        "Append error message to the result"

        json_diff = ""
        if d1 is not None and d2 is not None:
            json_diff = _json_diff(d1, d2)

        for line in error.splitlines():
            self.errors.append(line)
        self.errors.append(json_diff)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0

    def __str__(self):
        return "\n".join(self.errors)


# used with an "isinstance"/"is" comparison
class JSONCompareDirective(dict):
    """
    Helper class/type base.

    Classes derived from this are used in JSON diff to pass additional
    options to :py:func:`json_cmp`.  The idea is that instances of these
    can be placed in the "expected" data as "in-band" signal for various flags,
    e.g.::

       expect = {
           "something": [
               JSONCompareIgnoreExtraListitems(),
               1,
               2,
           ],
       }
       json_cmp(data, expect)
    """


class JSONCompareIgnoreContent(JSONCompareDirective):
    """
    Ignore list/dict content in JSON compare.
    """


class JSONCompareIgnoreExtraListitems(JSONCompareDirective):
    """
    Ignore any additional list items for this list.
    """


class JSONCompareListKeyedDict(JSONCompareDirective):
    """
    Compare this list by looking for matching items regardless of order.

    This assumes the list contains dicts, and these dicts have some keys that
    should be used as "index".  Items are matched up between both lists by
    looking for the same values on these keys.

    :param keying: dict keys to look up/match up.
    """

    keying: List[Union[int, str]]

    def __init__(self, *keying):
        super().__init__()
        self.keying = keying


class JSONCompareKeyShouldNotExist(JSONCompareDirective):
    """
    Expect key item should not exist.
    """


class JSONCompareDirectiveWrongSide(TypeError):
    """
    A JSONCompareDirective was seen on the "data" side of a compare.

    Directives need to go on the "expect" side.  Check argument order on
    :py:func:`json_cmp`.
    """


class JSONCompareUnexpectedDirective(TypeError):
    """
    Raised when hitting a JSONCompareDirective we weren't expecting.

    Some directives are only meaningful for dicts or lists, but not the other.
    """


def _json_diff(d1, d2):
    """
    Returns a string with the difference between JSON data.
    """
    json_format_opts = {
        "indent": 4,
        "sort_keys": True,
    }
    dstr1 = json.dumps(d1, **json_format_opts)
    dstr2 = json.dumps(d2, **json_format_opts)

    dstr1 = ("\n".join(dstr1.rstrip().splitlines()) + "\n").splitlines(1)
    dstr2 = ("\n".join(dstr2.rstrip().splitlines()) + "\n").splitlines(1)
    return get_textdiff(
        dstr2, dstr1, title1="Expected value", title2="Current value", n=0
    )


def _json_compare(d1: Any, d2: Any, result: JSONCompareResult, path: str = ""):
    """
    Recursive helper function for JSON comparison. Modifies the result object in-place
    to append errors.

    :param d1: value from json1
    :param d2: value from json2
    :param result: JSONCompareResult object to append errors
    :param path: current path in the JSON object being compared (used for error messages)
    """
    if isinstance(d2, JSONCompareDirective):
        raise JSONCompareDirectiveWrongSide(
            "JSONCompareDirective seen on the 'actual data' side of a compare."
        )

    if isinstance(d1, dict) and isinstance(d2, dict):
        _compare_dict(d1, d2, result, path)
    elif isinstance(d1, list) and isinstance(d2, list):
        _compare_list(d1, d2, result, path)
    else:
        _compare_values(d1, d2, result, path)


def _compare_dict(d1: dict, d2: dict, result: JSONCompareResult, path: str):
    for k, v2 in d2.items():
        p = f"{path}.{k}" if path else k
        if k not in d1:
            if isinstance(v2, JSONCompareKeyShouldNotExist):
                continue
            result.add_error(f"Key {p} not found in the actual data", d1, d2)
        else:
            v1 = d1[k]
            if isinstance(v2, JSONCompareDirective):
                continue
            _json_compare(v1, v2, result, p)


def _compare_list(d1: list, d2: list, result: JSONCompareResult, path: str):
    if len(d1) < len(d2) and not any(
        isinstance(x, JSONCompareIgnoreExtraListitems) for x in d2
    ):
        result.add_error(
            f"Actual data has fewer elements than expected:\n ({len(d1)} < {len(d2)}) at {path}",
            d1,
            d2,
        )
    for i, v2 in enumerate(d2):
        if i >= len(d1):
            if not isinstance(v2, JSONCompareIgnoreExtraListitems):
                result.add_error(
                    f"Actual data has fewer elements than expected:\n ({len(d1)} < {len(d2)}) at {path}",
                    d1,
                    d2,
                )
            break
        v1 = d1[i]
        p = f"{path}[{i}]"
        if isinstance(v2, JSONCompareDirective):
            if isinstance(v2, JSONCompareIgnoreExtraListitems):
                break
            if isinstance(v2, JSONCompareListKeyedDict):
                _compare_keyed_dict(v1, v2, result, p)
                continue
            raise JSONCompareUnexpectedDirective(
                f"Unexpected JSONCompareDirective in list at {path}"
            )
        _json_compare(v1, v2, result, p)


def _compare_keyed_dict(
    d1: dict, d2: JSONCompareListKeyedDict, result: JSONCompareResult, path: str
):
    keying = d2.keying
    keyed_d1 = {tuple(str(d1_item[k]) for k in keying): d1_item for d1_item in d1}
    keyed_d2 = {
        tuple(str(d2_item[k]) for k in keying): d2_item
        for d2_item in d2
        if all(k in d2_item for k in keying)
    }
    _json_compare(keyed_d1, keyed_d2, result, path)


def _compare_values(d1: Any, d2: Any, result: JSONCompareResult, path: str):
    if d1 != d2:
        result.add_error(
            f"Actual data mismatch at {path}.\nExpected: {d2}, Actual: {d1}", d1, d2
        )


def json_cmp(d1: Dict[str, Any], d2: Dict[str, Any]) -> Union[str, None]:
    """
    Compares two JSON objects, d1 and d2. Returns None if d1 matches all keys in d2,
    otherwise returns a string containing the errors.

    :param d1: json object
    :param d2: json subset which we expect
    :return: None if all keys that d1 has matches d2, otherwise a string containing the errors
    """

    result = JSONCompareResult()
    _json_compare(d1, d2, result)
    return None if not result.has_errors() else str(result)


# pylint: disable=too-many-locals
def text_rich_cmp(configs, rtr, out, expect, outtitle):
    lines = []
    for line in deindent(expect).split("\n"):
        items = line.split("$$")
        lre = []
        while len(items) > 0:
            lre.append(re.escape(items.pop(0)))
            if len(items) == 0:
                break
            expr = items.pop(0)
            if expr.startswith("="):
                expr = expr[1:]
                if expr.startswith(" "):
                    lre.append("\\s+")
                lre.append(re.escape(str(configs.eval(rtr, expr))))
                if expr.endswith(" "):
                    lre.append("\\s+")
            else:
                lre.append(expr)
        lines.append((line, "".join(lre)))

    x_got, x_exp = [], []
    fail = False

    for i, out_line in enumerate(out.split("\n")):
        if i >= len(lines):
            x_got.append(out_line)
            fail = True
            continue

        ref_line, ref_re = lines[i]
        if re.match("^" + ref_re + "$", out_line):
            x_got.append(out_line)
            x_exp.append(out_line)
        else:
            x_got.append(out_line)
            x_exp.append(ref_line)
            fail = True

    if not fail:
        return None

    return TopotatoCLICompareFail(
        "\n" + get_textdiff(x_got, x_exp, title1=outtitle, title2="expected")
    )


_env_path = os.environ["PATH"].split(":")


def exec_find(name, stacklevel=1):
    for p in _env_path:
        pname = os.path.join(p, name)
        if os.access(pname, os.X_OK):
            logger.debug(
                "executable %s found: %s",
                shlex.quote(name),
                shlex.quote(pname),
                stacklevel=stacklevel + 1,
            )
            return pname

    logger.warning("executable %s not found in PATH", shlex.quote(name))
    return None


def get_dir(session, optname, ininame):
    basedir = os.getcwd()
    val = session.config.getoption(optname)
    if not val:
        basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        val = session.config.getini(ininame)

    if val is None:
        return None
    if not os.path.isabs(val):
        val = os.path.abspath(os.path.join(basedir, val))
    return val


class EnvcheckResult:
    def __init__(self):
        super().__init__()
        self.warnings = []
        self.errors = []

    def __bool__(self):
        return len(self.errors) == 0

    def warning(self, *args):
        self.warnings.append(args)

    def error(self, *args):
        self.errors.append(args)


_PathLike = Union[os.PathLike, str, bytes]


class TmpName:
    """
    Create filename for a temporary file in the same directory.

    The filename will be prefixed with ``.`` and suffixed with ``.tmp``.
    """

    filename: _PathLike

    def __init__(self, filename: _PathLike):
        self.filename = filename

    def __fspath__(self) -> str:
        filename = os.fsdecode(self.filename)
        dirname, basename = os.path.split(filename)
        return os.path.join(dirname, "." + basename + ".tmp")


class LockedFile:
    """
    Create a file and hold a POSIX advisory lock on it.

    The purpose of this is that the F_GETLK fcntl can retrieve the PID of the
    process holding the lock, and it automatically disappears when the process
    exits (even if it crashes and the file is still there).

    This should be used either as a context manager (``with LockedFile(...):``)
    or through the :py:func:`lock` method (which deletes the file at exit.)

    Has a "depth" counter to allow nested "lock"/"unlock" operations.
    """

    filename: _PathLike
    """
    Original file name passed when constructing.  Not used further.
    """
    _dir_fd: int
    """
    Directory file descriptor that this file will reside in.
    """
    _basename: _PathLike
    """
    File name relative to _dir_fd.
    """

    def __init__(self, filename: _PathLike, dir_fd=None):
        self.filename = filename
        self._depth = 0
        self._fd = None

        if dir_fd is None:
            dirname, basename = os.path.split(os.path.abspath(filename))
            self._basename = basename
            self._dir_fd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY)
        else:
            self._basename = filename
            self._dir_fd = os.dup(dir_fd)

    def __del__(self):
        os.close(self._dir_fd)

    def _open(self):
        self._depth += 1
        if self._fd is not None:
            return

        tmpname = TmpName(self._basename)
        try:

            def _opener(path, flags):
                return os.open(path, flags, mode=0o666, dir_fd=self._dir_fd)

            # pylint: disable=unspecified-encoding,consider-using-with
            self._fd = open(tmpname, "w", opener=_opener)
            fcntl.lockf(self._fd, fcntl.LOCK_EX)
            # lock file (and write data) first, then put it in place
            # => no intermediate race where the file could be seen by an
            #    external process, but without the lock held/data in it
            #
            # renameat2(RENAME_NOREPLACE) would be great here, but python
            # does not provide access to it
            os.rename(
                tmpname,
                self._basename,
                src_dir_fd=self._dir_fd,
                dst_dir_fd=self._dir_fd,
            )

        except:
            try:
                os.unlink(tmpname, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass
            try:
                os.unlink(self._basename, dir_fd=self._dir_fd)
            except FileNotFoundError:
                pass
            raise

    def _close(self):
        self._depth -= 1
        if self._depth:
            return

        os.unlink(self._basename, dir_fd=self._dir_fd)
        # delete file before implicit unlock in close()
        # => avoids the same kind of race as in _open
        self._fd.close()
        self._fd = None

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self._close()

    def lock(self):
        """
        Create and lock file.

        Registers with python atexit module to delete the file when the process
        exits.  Using lock() without any unlock() is normal use for situations
        where some file should be held for the entire duration of the process.
        """
        atexit.register(self._close)
        self._open()

        return self

    def unlock(self):
        """
        Unlock and delete file.
        """
        self._close()
        atexit.unregister(self._close)


# pylint: disable=too-many-instance-attributes
class AtomicPublishFile:
    """
    Write a file and move it in place (to "publish") with rename().

    The idea here is that when the file is seen, the contents have already
    been written into it.
    """

    filename: _PathLike
    """
    Original file name passed when constructing.  Not used further.
    """
    _dir_fd: int
    """
    Directory file descriptor that this file will reside in.
    """
    _basename: _PathLike
    """
    File name relative to _dir_fd.
    """
    _tmpname: TmpName
    """
    Temporary file name, also relative to _dir_fd.
    """

    def __init__(self, filename, *args, dir_fd=None, **kwargs):
        self.filename = filename
        self._args = args
        self._kwargs = kwargs

        self._fd = None
        if dir_fd is not None:
            self._basename = filename
            self._dir_fd = os.dup(dir_fd)
        else:
            dirname, basename = os.path.split(os.path.abspath(filename))
            self._basename = basename
            self._dir_fd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY)

        self._tmpname = TmpName(self._basename)

    def __del__(self):
        os.close(self._dir_fd)

    def __enter__(self):
        def _opener(path, flags):
            return os.open(path, flags, mode=0o666, dir_fd=self._dir_fd)

        # pylint: disable=unspecified-encoding
        self._fd = open(self._tmpname, *self._args, opener=_opener, **self._kwargs)
        return self._fd

    def __exit__(self, exc_type, exc_value, tb):
        self._fd.close()

        if exc_type is None:
            try:
                os.rename(
                    self._tmpname,
                    self.filename,
                    src_dir_fd=self._dir_fd,
                    dst_dir_fd=self._dir_fd,
                )
            except:
                try:
                    os.unlink(self._tmpname, dir_fd=self._dir_fd)
                except FileNotFoundError:
                    pass
                raise
        else:
            try:
                os.unlink(self._tmpname, dir_fd=self._dir_fd)
            except OSError:
                # already handling some exception, don't make things confusing
                pass


class Forked:
    """
    Context manager to execute some code in a forked child process.

    Use as::

       with Forked('text for exception') as is_child:
           if is_child:
               ...

    The parent process will wait for the child code to complete executing.
    If the exit code is nonzero, subprocess.CalledProcessError will be raised.
    Any exception in the child is printed and converted into exit code 1.

    Used in topotato to fork+exec some pieces in namespaces where nsenter is
    not a good fit.
    """

    def __init__(self, cmd):
        self.cmd = cmd
        self.childpid = None

    def __enter__(self):
        self.childpid = os.fork()
        return self.childpid == 0

    def __exit__(self, typ_, value, tb):
        if self.childpid:
            _, status = os.waitpid(self.childpid, 0)
            ec = os.waitstatus_to_exitcode(status)
            if ec != 0:
                raise subprocess.CalledProcessError(ec, self.cmd)
        elif typ_ is None:
            os._exit(0)
        else:
            sys.stderr.write("Exception in forked child:\n")
            traceback.print_exception(typ_, value, tb)
            os._exit(1)
