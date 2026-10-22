import os
from typing import Dict, List, Optional, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding
from outflank_stage1.task.exceptions import TaskInvalidArgumentsException


_SCRIPT_BASE_PATH = os.path.dirname(os.path.abspath(__file__))


class IntuneExchangeBOF(BaseBOFTask):
    """Exchange a MAM token for an Intune enrollment token."""

    def __init__(self):
        super().__init__("intune-exchange", base_binary_name="exchange")
        self.set_base_path(_SCRIPT_BASE_PATH)

        self.parser.description = (
            "Exchange a MAM token for an Intune enrollment token via the "
            "TokenRenewalService. Auto-discovers the IWService host from "
            "IME logs and the device ID from the MDM enrollment certificate."
        )

        self.parser.add_argument(
            "mam_token",
            help="MAM access token (from askwam BOF)",
        )
        self.parser.add_argument(
            "--host", default="",
            help="IWService host override (default: auto-discover from IME logs)",
        )

        self.parser.epilog = (
            "Example usage:\n"
            "  intune-exchange <mam-token>\n"
            "  intune-exchange <mam-token> --host fef.amsub0302.manage.microsoft.com\n\n"
            "Full chain:\n"
            "  1. askwam --client-id 9ba1a5c7-... --scope d4ebce55-.../.default\n"
            "  2. intune-exchange <mam-token>\n"
            "  3. intune-apps <enrollment-token> list\n\n"
            "Notes:\n"
            "  The MAM token expires quickly. Use it within a few minutes.\n"
            "  The enrollment token output is used by intune-apps.\n"
        )

    def validate_arguments(self, arguments: List[str]):
        super().validate_arguments(arguments)
        args, _ = self.parser.parse_known_args(arguments)
        if not args.mam_token:
            raise TaskInvalidArgumentsException("MAM token is required")

    def _encode_arguments_bof(
        self, arguments: List[str]
    ) -> List[Tuple[BOFArgumentEncoding, str]]:
        args, _ = self.parser.parse_known_args(arguments)
        # BOF expects: zz (mam_token, host_override)
        return [
            (BOFArgumentEncoding.STR, args.mam_token),
            (BOFArgumentEncoding.STR, args.host),
        ]

    def run(self, arguments: List[str]):
        args, _ = self.parser.parse_known_args(arguments)
        if args.host:
            self.append_response(
                f"[*] Exchanging MAM token via {args.host}...\n"
            )
        else:
            self.append_response(
                "[*] Exchanging MAM token (auto-discovering host)...\n"
            )
        super().run(arguments)

    def get_gui_elements(self) -> Optional[Dict]:
        return None
