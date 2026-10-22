import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))

VALID_COMMANDS = ("list", "install", "uninstall", "status")


class IntuneAppsBOF(BaseBOFTask):
    """List, install, uninstall, or check status of Intune apps."""

    def __init__(self):
        super().__init__("intune-apps", base_binary_name="apps")
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "List, install, uninstall, or check status of Intune apps via "
            "the IWService REST API. Auto-discovers the IWService host and "
            "device ID. Requires an enrollment token from intune-exchange."
        )

        self.parser.add_argument(
            "token",
            help="Enrollment token (from intune-exchange)",
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
            "  intune-apps <token> list\n"
            "  intune-apps <token> status <app-guid>\n"
            "  intune-apps <token> uninstall <app-guid>\n"
            "  intune-apps <token> install <app-guid>\n"
            "  intune-apps <token> list --host fef.xxx.manage.microsoft.com\n\n"
            "Full chain:\n"
            "  1. askwam --client-id 9ba1a5c7-... --scope d4ebce55-.../.default\n"
            "  2. intune-exchange <mam-token>\n"
            "  3. intune-apps <token> list\n"
            "  4. intune-apps <token> uninstall <app-guid>\n"
            "  5. intune-apps <token> status <app-guid>   (wait for ApprovedForInstall)\n"
            "  6. intune-race                              (upload payload, arm watcher)\n"
            "  7. intune-apps <token> install <app-guid>\n\n"
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
        # BOF expects: zzzz (token, command, app_guid, host_override)
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
