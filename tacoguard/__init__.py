"""TacoGuard: a second-opinion malware scanner for Windows."""
import os as _os

__version__ = "0.3.0"
APP_NAME = "TacoGuard"

# The ML model (LightGBM, OpenMP) scores one file at a time. With OpenMP's defaults it starts a
# thread per CPU core that keeps spinning after each score: measured 2026-11-24, 2.9 s of CPU in
# 5 idle seconds and 822 MB committed memory. One passive thread: 0 s idle, 77 MB. Set before
# lightgbm is imported anywhere; an explicit environment setting still wins.
_os.environ.setdefault("OMP_NUM_THREADS", "1")
_os.environ.setdefault("OMP_WAIT_POLICY", "PASSIVE")
