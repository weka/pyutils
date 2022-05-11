
from . import _version
__version__ = _version.get_versions()['version']

from logging import getLogger, NullHandler
log = getLogger('wekapyutils')
log.addHandler(NullHandler())

from . import pushd
from . import announce
