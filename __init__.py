from .arches.nanomips import Nanomips
from .arches.tiamat import Tiamat
from .arches.tiamat import TiamatView

Nanomips.register()
TiamatView.register()
Tiamat.register()