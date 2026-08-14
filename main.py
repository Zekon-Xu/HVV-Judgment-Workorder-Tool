#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""研判工单自动生成工具 — 启动入口（只生成工单与处置意见，不执行处置）

Designed By Zekon_Sec For 2026 HVV
"""

from __future__ import annotations

import sys
from pathlib import Path

# Designed By Zekon_Sec For 2026 HVV
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    # Designed By Zekon_Sec For 2026 HVV — runtime bootstrap
    from app.settings_store import ensure_runtime_files

    ensure_runtime_files()
    from app.gui import WorkOrderApp

    app = WorkOrderApp()
    app.mainloop()


if __name__ == "__main__":
    main()
