"""
shifts.py - Admin roster and shift schedules.
All times are US Eastern Time (ET).
"""

from datetime import time

ADMINS = {
    1615926408: {"name": "Daniel",  "username": "danikav"},
}

ALL_IDS = list(ADMINS.keys())

SHIFTS = [
    {
        "name":   "Morning",
        "start":  time(6, 0),
        "end":    time(14, 0),
        "days":   [0, 1, 2, 3, 4],
        "admins": ALL_IDS,
    },
    {
        "name":   "Afternoon",
        "start":  time(14, 0),
        "end":    time(22, 0),
        "days":   [0, 1, 2, 3, 4],
        "admins": ALL_IDS,
    },
    {
        "name":   "Night",
        "start":  time(22, 0),
        "end":    time(6, 0),
        "days":   [0, 1, 2, 3, 4, 5, 6],
        "admins": ALL_IDS,
    },
    {
        "name":   "Weekend",
        "start":  time(8, 0),
        "end":    time(20, 0),
        "days":   [5, 6],
        "admins": ALL_IDS,
    },
]

TIMEZONE = "America/New_York"

# MAIN_ADMIN_ID is kept as a set so "user.id in MAIN_ADMIN_ID" works correctly everywhere
MAIN_ADMIN_ID = {8422260316, 7808593054, 7769230456, 1401145589}

SUPER_ADMINS = {8422260316, 7808593054, 7769230456, 1401145589}  # all super admins
