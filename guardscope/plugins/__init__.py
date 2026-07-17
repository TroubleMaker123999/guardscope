"""Plugin protocol and registry.

A plugin enriches or annotates a :class:`~guardscope.core.models.Finding`
after parsing. The built-in :mod:`~guardscope.plugins.sample` plugin shows
the contract.
"""

from .base import Plugin, register_plugin, get_plugin, list_plugins, run_plugins
from .sample import SamplePlugin

register_plugin(SamplePlugin())

__all__ = ["Plugin", "register_plugin", "get_plugin", "list_plugins", "run_plugins", "SamplePlugin"]