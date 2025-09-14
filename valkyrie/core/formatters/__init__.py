from .base import ResultFormatter
from .sarif import SARIFFormatter
from .html import HTMLFormatter
from .json import JSONFormatter


####    GET FORMMATER
def get_formatter(name: str) -> ResultFormatter:
    """Return a Result formatter class by name"""

    mapping = {
        'json': JSONFormatter,
        'html': HTMLFormatter,
        'sarif': SARIFFormatter 
    }

    return mapping.get(name, SARIFFormatter)

__all__ = [
    ResultFormatter,
    SARIFFormatter,
    HTMLFormatter,
    JSONFormatter,
    get_formatter
]