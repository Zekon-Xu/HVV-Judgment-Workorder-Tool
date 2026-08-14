"""Open a selected page for manual/screenshot layout checks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.gui import WorkOrderApp


PAGES = {
    "work": "工单生成",
    "batch": "批量生成",
    "config": "配置中心",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("page", choices=PAGES, default="work", nargs="?")
    parser.add_argument("--brand", action="store_true")
    args = parser.parse_args()
    app = WorkOrderApp()
    app.settings["tray_enabled"] = False
    label = PAGES[args.page]
    for page in (app.page_work, app.page_batch, app.page_config):
        page.pack_forget()
    getattr(app, f"page_{args.page}").pack(fill="both", expand=True)
    app.tab_seg.set(label)
    if args.page == "config":
        app.after_idle(app._scroll_config_top)
    if args.brand:
        app.after(300, app._preview_branding)
    app.mainloop()


if __name__ == "__main__":
    main()
