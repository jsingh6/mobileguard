# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Language-specific pattern detectors for MobileGuard.

Each detector module exposes a single `detect(file_path, content) -> list[Finding]`
function. Detectors use regex pattern matching only — no LLM calls. The `--llm` flag
on `mobileguard scan` adds a Claude API pass on top of these results.
"""

from mobileguard.detectors.dart import detect as detect_dart
from mobileguard.detectors.javascript import detect as detect_javascript
from mobileguard.detectors.kotlin import detect as detect_kotlin
from mobileguard.detectors.swift import detect as detect_swift

__all__ = ["detect_dart", "detect_javascript", "detect_kotlin", "detect_swift"]
