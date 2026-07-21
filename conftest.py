"""Root conftest: register near's own pytest fixtures AFTER coverage starts.

The ``near`` pytest11 entry point is blocked in addopts (``-p no:near``)
because entry-point plugins are imported during pytest's plugin
registration, before pytest-cov can start its collector — so autoloading it
here would execute every module-level statement in src/near unmeasured and
tank reported coverage by ~40 points. Loading the same module via
``pytest_plugins`` registers the identical fixtures once coverage is already
collecting. Downstream users are unaffected (their runs autoload the entry
point normally), and the entry-point path is still proven end to end by
tests/plugin/test_sandbox_plugin.py, whose inner pytester run inherits
neither this repo's addopts nor this conftest.
"""

pytest_plugins = ["near._pytest_plugin"]
