# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Real controller-only read capabilities for observed DeepSeek JSON actions.

No HTTP route accepts AdvisoryAction. The owning advisory orchestrator creates
it after recording the actual provider response. The required authorization
callback applies the registered capability policy before each read.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import asdict

from .advisory_runtime import AdvisoryAction
from .deepseek import MODEL, DeepSeekRole
from .memory import SOURCE_ID, Caller, MemoryFacade
from .native_launcher import _canonical
from .tool_services_runtime import ClangdClient, ToolServiceDenied, _path, _roots, _validate_tool

# The actual controller JSON action protocol, used for inventory freezing.
# These describe the existing validators below, not provider-native tool schemas.
ADVISORY_ACTION_SCHEMAS = (
    {
        "name": "local_read",
        "input_schema": {
            "type": "object",
            "properties": {
                "operation": {"type": "string", "enum": ["read", "list", "search"]},
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1, "maximum": 10000000},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 2000},
                "after": {"type": "string", "maxLength": 4096, "pattern": r"^[^/\\]*$"},
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 1000},
                "query": {"type": "string", "minLength": 1, "maxLength": 1000},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["operation", "path"],
            "additionalProperties": False,
            "oneOf": [
                {
                    "properties": {"operation": {"const": "read"}},
                    "not": {
                        "anyOf": [
                            {"required": [key]}
                            for key in ("after", "max_entries", "query", "max_results")
                        ]
                    },
                },
                {
                    "properties": {"operation": {"const": "list"}},
                    "not": {
                        "anyOf": [
                            {"required": [key]}
                            for key in ("start_line", "max_lines", "query", "max_results")
                        ]
                    },
                },
                {
                    "properties": {"operation": {"const": "search"}},
                    "required": ["query"],
                    "not": {
                        "anyOf": [
                            {"required": [key]}
                            for key in ("start_line", "max_lines", "after", "max_entries")
                        ]
                    },
                },
            ],
        },
    },
    {
        "name": "clangd_read",
        "input_schema": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["document_symbols", "hover", "definition", "references"],
                },
                "path": {"type": "string"},
                "line": {"type": "integer", "minimum": 0, "maximum": 1000000},
                "character": {"type": "integer", "minimum": 0, "maximum": 1000000},
            },
            "required": ["operation", "path"],
            "additionalProperties": False,
            "oneOf": [
                {
                    "properties": {"operation": {"const": "document_symbols"}},
                    "not": {"anyOf": [{"required": ["line"]}, {"required": ["character"]}]},
                },
                {
                    "properties": {"operation": {"enum": ["hover", "definition", "references"]}},
                    "required": ["line", "character"],
                },
            ],
        },
    },
    *(
        {
            "name": name,
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 1000, "pattern": r"\S"}
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        }
        for name in ("gbrain_recall", "gbrain_search")
    ),
)

_SOURCE_QUERY = r"""import json,os,posixpath,stat,sys
payload=json.loads(sys.argv[1]);a=payload["arguments"];roots=payload["roots"];path=a["path"]
if posixpath.normpath(path)!=path or "//" in path or not any(path==root or path.startswith(root+"/") for root in roots): raise ValueError("scope")
def open_path(value,directory=False):
 parts=value.split("/")[1:];fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
 try:
  for index,part in enumerate(parts):
   flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
   if index<len(parts)-1 or directory: flags|=os.O_DIRECTORY
   child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
  result=fd;fd=None;return result
 finally:
  if fd is not None: os.close(fd)
def read_file(value):
 fd=open_path(value)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size>1048576: raise ValueError("bounded regular source required")
  result=b""
  while len(result)<=1048576:
   part=os.read(fd,min(65536,1048577-len(result)))
   if not part: break
   result+=part
  after=os.fstat(fd)
  if len(result)>1048576 or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise ValueError("source changed")
  return result.decode("utf8")
 finally: os.close(fd)
def entries(value):
 fd=open_path(value,True)
 try:
  with os.scandir(fd) as iterator:
   found=[]
   for entry in iterator:
    if len(found)>=20000: raise ValueError("directory enumeration bound")
    mode=entry.stat(follow_symlinks=False).st_mode
    if stat.S_ISREG(mode) or stat.S_ISDIR(mode): found.append((entry.name,stat.S_ISDIR(mode)))
  return sorted(found)
 finally: os.close(fd)
operation=a["operation"];result={"operation":operation,"path":path,"truncated":False}
if operation=="read":
 lines=read_file(path).splitlines();start=a.get("start_line",1);limit=a.get("max_lines",300)
 result["lines"]=[{"line":i+1,"text":line[:8192],"line_truncated":len(line)>8192} for i,line in enumerate(lines) if start<=i+1<start+limit]
 result["truncated"]=start+limit-1<len(lines)
elif operation=="list":
 after=a.get("after","");limit=a.get("max_entries",500);found=[(name,directory) for name,directory in entries(path) if name>after]
 result["entries"]=[{"name":name,"type":"directory" if directory else "file"} for name,directory in found[:limit]]
 result["truncated"]=len(found)>limit
 result["next_after"]=found[limit-1][0] if result["truncated"] else None
elif operation=="search":
 query=a["query"];limit=a.get("max_results",200);queue=[(path,0)];matches=[];visited=0;read_bytes=0;skipped=0
 while queue and len(matches)<limit:
  folder,depth=queue.pop()
  for name,directory in entries(folder):
   visited+=1
   if visited>20000 or read_bytes>33554432: result["truncated"]=True;queue=[];break
   current=folder+"/"+name
   if directory:
    if depth<64: queue.append((current,depth+1))
    else: result["truncated"]=True
    continue
   try: content=read_file(current)
   except (UnicodeError,OSError,ValueError): skipped+=1;continue
   read_bytes+=len(content.encode("utf8"))
   for number,line in enumerate(content.splitlines(),1):
    if query in line:
     matches.append({"path":current,"line":number,"text":line[:8192],"line_truncated":len(line)>8192})
     if len(matches)>=limit: result["truncated"]=True;break
   if len(matches)>=limit: break
 result["matches"]=matches
 result["skipped_files"]=skipped
else: raise ValueError("operation")
encoded=json.dumps(result,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
if len(encoded)>1048576: raise ValueError("response bound")
sys.stdout.buffer.write(encoded)
"""


class AdvisoryTools:
    def __init__(
        self,
        api,
        *,
        container_id: str,
        source_roots: Sequence[str],
        task_id: str,
        attempt_id: str,
        clangd: ClangdClient,
        memory: MemoryFacade,
        structural_terms: tuple[str, ...],
        authorize: Callable[[AdvisoryAction, dict], bool],
    ):
        self.source_roots = _roots(source_roots)
        if (
            not isinstance(clangd, ClangdClient)
            or not isinstance(memory, MemoryFacade)
            or clangd.container_id != container_id
            or clangd.source_roots != self.source_roots
            or not callable(authorize)
            or not isinstance(structural_terms, tuple)
            or not structural_terms
            or any(type(term) is not str or not term.strip() for term in structural_terms)
        ):
            raise ValueError(
                "same-task clangd, actual memory facade and registered authorizer required"
            )
        self.api, self.container_id, self.task_id, self.attempt_id = (
            api,
            container_id,
            task_id,
            attempt_id,
        )
        self.clangd, self.memory, self.structural_terms, self.authorize = (
            clangd,
            memory,
            structural_terms,
            authorize,
        )

    def callbacks(self):
        return {
            "local_read": self.local_read,
            "clangd_read": self.clangd_read,
            "gbrain_recall": self.gbrain_recall,
            "gbrain_search": self.gbrain_search,
        }

    def _admit(self, name, args, role, action):
        if (
            type(action) is not AdvisoryAction
            or type(args) is not dict
            or type(role) is not DeepSeekRole
            or action.role is not role
            or action.name != name
            or action.task_id != self.task_id
            or action.attempt_id != self.attempt_id
            or action.arguments_sha256 != hashlib.sha256(_canonical(args)).hexdigest()
            or self.authorize(action, dict(args)) is not True
        ):
            raise ToolServiceDenied("controller advisory read authorization denied")

    def _source_path(self, path, *, directory=False):
        if directory and path in self.source_roots:
            return path
        return _path(path, self.source_roots)

    def local_read(self, args, role, action):
        if type(args) is not dict or args.get("operation") not in {"read", "list", "search"}:
            raise ToolServiceDenied("invalid readonly source operation")
        operation = args["operation"]
        optional = {
            "read": {"start_line", "max_lines"},
            "list": {"after", "max_entries"},
            "search": {"query", "max_results"},
        }[operation]
        if not {"operation", "path"} <= set(args) or set(args) - {"operation", "path"} - optional:
            raise ToolServiceDenied("invalid source arguments")
        self._source_path(args["path"], directory=operation != "read")
        limits = {
            "start_line": 10000000,
            "max_lines": 2000,
            "max_entries": 1000,
            "max_results": 200,
        }
        if any(
            key in args and (type(args[key]) is not int or not 1 <= args[key] <= limit)
            for key, limit in limits.items()
        ):
            raise ToolServiceDenied("source result bound invalid")
        if operation == "search" and (
            type(args.get("query")) is not str or not 1 <= len(args["query"]) <= 1000
        ):
            raise ToolServiceDenied("bounded literal source query required")
        if "after" in args and (
            type(args["after"]) is not str
            or len(args["after"]) > 4096
            or "/" in args["after"]
            or "\\" in args["after"]
        ):
            raise ToolServiceDenied("invalid directory cursor")
        self._admit("local_read", args, role, action)
        command = [
            "/usr/bin/timeout",
            "--signal=KILL",
            "20s",
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            _SOURCE_QUERY,
            _canonical({"roots": self.source_roots, "arguments": args}).decode(),
        ]
        created = self.api.exec_create(
            self.container_id,
            cmd=command,
            user="agent",
            stdin=False,
            stdout=True,
            stderr=False,
            tty=False,
            workdir=self.source_roots[0],
            environment={"PATH": "/usr/bin:/bin"},
        )
        data = self.api.exec_start(created["Id"], stream=False, tty=False)
        completed = self.api.exec_inspect(created["Id"])
        if (
            completed.get("Running") is not False
            or completed.get("ExitCode") != 0
            or type(data) is not bytes
            or len(data) > 1048576
        ):
            raise ToolServiceDenied("bounded source read unavailable")
        result = json.loads(data)
        if type(result) is not dict or result.get("operation") != operation:
            raise ToolServiceDenied("source reader result malformed")
        return result

    def clangd_read(self, args, role, action):
        if type(args) is not dict or type(args.get("operation")) is not str:
            raise ToolServiceDenied("clangd operation required")
        operation = args["operation"]
        parameters = {key: value for key, value in args.items() if key != "operation"}
        _validate_tool(operation, parameters)
        self._source_path(parameters["path"])
        self._admit("clangd_read", args, role, action)
        return self.clangd.invoke(operation, parameters)

    def _memory_read(self, name, args, role, action):
        if (
            type(args) is not dict
            or set(args) != {"query"}
            or type(args["query"]) is not str
            or not 1 <= len(args["query"].strip()) <= 1000
        ):
            raise ToolServiceDenied("bounded memory query required")
        self._admit("gbrain_" + name, args, role, action)
        selections = self.memory.model_tool(
            name,
            args["query"],
            caller=Caller.CHILD,
            structural_terms=self.structural_terms,
            task_id=self.task_id,
            attempt_id=self.attempt_id,
            request_id=action.action_id,
            model_id=MODEL,
        )
        return {"source_id": SOURCE_ID, "results": [asdict(selection) for selection in selections]}

    def gbrain_recall(self, args, role, action):
        return self._memory_read("recall", args, role, action)

    def gbrain_search(self, args, role, action):
        return self._memory_read("search", args, role, action)
