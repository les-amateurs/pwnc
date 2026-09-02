"""Compatibility import for the rewritten Teemo extractor."""

from .extractor import BinaryNinjaExtractor, ExtractionError, extract_document
from .type_export import BinjaTypeExporter

__all__ = ["BinaryNinjaExtractor", "BinjaTypeExporter", "ExtractionError", "extract_document"]
