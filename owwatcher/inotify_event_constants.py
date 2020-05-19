import inotify.constants as ic


class InotifyEventConstants:
    IN_ATTRIB = ic.MASK_LOOKUP[ic.IN_ATTRIB]
    IN_CLOSE_WRITE = ic.MASK_LOOKUP[ic.IN_CLOSE_WRITE]
    IN_CREATE = ic.MASK_LOOKUP[ic.IN_CREATE]
    IN_DELETE = ic.MASK_LOOKUP[ic.IN_DELETE]
    IN_ISDIR = ic.MASK_LOOKUP[ic.IN_ISDIR]
    IN_MOVED_TO = ic.MASK_LOOKUP[ic.IN_MOVED_TO]
    IN_OPEN = ic.MASK_LOOKUP[ic.IN_OPEN]
