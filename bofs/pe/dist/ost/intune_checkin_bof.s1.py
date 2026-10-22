import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding


VALID_OPS = ("checkin", "available", "both")


def _resolve_binary_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(script_dir).lower() == "ost":
        return os.path.normpath(os.path.join(script_dir, "../pe"))
    return script_dir


class IntuneCheckinPEBOF(BaseBOFTask):
    """Trigger an IME check-in via the WCF named pipe. BOF-PE version."""

    def __init__(self):
        super().__init__(
            "intune-checkin-pe",
            base_binary_name="checkin",
            base_binary_path=_resolve_binary_path(),
        )

        self.parser.description = (
            "Trigger an Intune Management Extension check-in by calling "
            "CheckInAsync and/or AvailableAppCheckInAsync on the IME "
            "StatusService WCF named pipe. Forces IME to process queued "
            "app installs immediately instead of waiting for the next "
            "scheduled check-in cycle. BOF-PE version."
        )

        self.parser.add_argument(
            "operation",
            nargs="?",
            default="both",
            choices=VALID_OPS,
            help="Which check-in to trigger (default: both)",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  intune-checkin-pe                (trigger both check-ins)\n"
            "  intune-checkin-pe checkin        (CheckInAsync only)\n"
            "  intune-checkin-pe available      (AvailableAppCheckInAsync only)\n\n"
            "Usage in the chain:\n"
            "  1. intune-race-pe               (arm watcher with payload)\n"
            "  2. intune-apps-pe <token> install <app-guid>\n"
            "  3. intune-checkin-pe             (force immediate processing)\n\n"
            "Notes:\n"
            "  The named pipe denies the NETWORK SID, so this only works\n"
            "  from an interactive or service logon context (not WinRM).\n"
        )

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        args = self.parser.parse_args(arguments)
        return [
            (BOFArgumentEncoding.STR, args.operation),
        ]

    def run(self, arguments: List[str]):
        args = self.parser.parse_args(arguments)
        self.append_response(
            f"[*] Triggering IME check-in (operation: {args.operation})...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None
