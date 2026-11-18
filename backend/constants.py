from backend.exports import _jsonify, csvify, xmlify, listify, xlsxify, proxify
from backend.reports import xlsx, pushpin

EXPORTS = {
    'json': _jsonify,
    'xml': xmlify,
    'csv': csvify,
    'list': listify,
    'xlsx': xlsxify,
    'proxy': proxify,
}

REPORTS = {
    'xlsx': xlsx,
    'pushpin': pushpin,
}
