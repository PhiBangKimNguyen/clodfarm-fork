"""Legacy execution is allowed only after an explicit isolation opt-out."""

import os


def isolation_required(env=None):
    values = os.environ if env is None else env
    return str(values.get("FARM_REQUIRE_ISOLATION", "")).strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def tier0(env=None):
    values = os.environ if env is None else env
    return str(values.get("FARM_TIER0", "0")).strip().lower() not in {"0", "false", "no", "off"}
