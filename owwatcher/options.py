import collections
import os

Args = collections.namedtuple('Args', 'dirs perms_mask syslog_port syslog_server tcp log_file debug')

class Options:
    INVALID_DIR_ERROR = "The directory '%s' does not exist."
    PERMS_FORMAT_MSG = "The permissions mask must be an octal integer (e.g. 755) between 0 and 777 inclusive."
    INVALID_PERMS_ERROR = "%s is an invalid permissions mask. " + PERMS_FORMAT_MSG
    INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
    INVALID_PROTOCOL_ERROR = "Unknown protocol '%s'. Valid protocols are 'udp' or 'tcp'."
    INVALID_DEBUG_ERROR = "'%s' is not a valid value for the debug option. Valid values are 'True' or 'False'."


    def __init__(self, args, config, is_snap=False):
        defaults = Options._get_defaults(is_snap)

        self.dirs = Options._merge_dirs_option(args, config, defaults.dirs)
        self.perms_mask = Options._merge_perms_mask_option(args, config, defaults.perms_mask)
        self.syslog_port = Options._merge_syslog_port_option(args, config, defaults.syslog_port)
        self.syslog_server = Options._merge_syslog_server_option(args, config, defaults.syslog_server)
        self.log_file = Options._merge_log_file_option(args, config, defaults.log_file)
        self.protocol = Options._merge_protocol_option(args, config, defaults.tcp)
        self.debug = Options._merge_debug_option(args, config, defaults.debug)

        self._raise_on_invalid_options()

    @staticmethod
    def _merge_dirs_option(args, config, default):
        return Options._merge_single_option('dirs', args.dirs, config, default).split(',')

    @staticmethod
    def _merge_perms_mask_option(args, config, default):
        mask = Options._merge_single_option('perms_mask', args.perms_mask, config, default)

        if isinstance(mask, int) or mask is None:
            return mask

        try:
            return int(mask, 8)
        except ValueError:
            raise TypeError(Options.PERMS_FORMAT_MSG)

    @staticmethod
    def _merge_syslog_port_option(args, config, default):
        return int(Options._merge_single_option('syslog_port', args.syslog_port, config, default))

    @staticmethod
    def _merge_syslog_server_option(args, config, default):
        return Options._merge_single_option('syslog_server', args.syslog_server, config, default)

    @staticmethod
    def _merge_log_file_option(args, config, default):
        return Options._merge_single_option('log_file', args.log_file, config, default)

    @staticmethod
    def _merge_single_option(option_name, arg, config, default):
        if arg is not None:
            return arg

        if option_name in config['DEFAULT']:
            return config['DEFAULT'][option_name]

        return default

    @staticmethod
    def _merge_protocol_option(args, config, default):
        if args.tcp:
            return "tcp"

        if 'protocol' in config['DEFAULT']:
            return config['DEFAULT']['protocol'].lower()

        if default:
            return "tcp"

        return "udp"

    @staticmethod
    def _merge_debug_option(args, config, default):
        if args.debug:
            return True

        if 'debug' in config['DEFAULT']:
            Options._raise_on_invalid_debug(config['DEFAULT']['debug'])
            return True if config['DEFAULT']['debug'] == 'True' else False

        return default

    def _raise_on_invalid_options(self):
        self._raise_on_invalid_perms_mask()
        self._raise_on_invalid_syslog_port()
        self._raise_on_invalid_protocol()
        self._raise_on_invalid_dir()

    def _raise_on_invalid_perms_mask(self):
        if self.perms_mask is None:
            return

        if not isinstance(self.perms_mask, int):
            raise TypeError(Options.PERMS_FORMAT_MSG)

        if self.perms_mask < 0 or self.perms_mask > 0o777:
                raise ValueError(Options.INVALID_PERMS_ERROR % format(self.perms_mask, 'o'))

    def _raise_on_invalid_syslog_port(self):
        if not isinstance(self.syslog_port, int):
            raise TypeError(Options.INVALID_PORT_ERROR)

        if self.syslog_port < 1 or self.syslog_port > 65535:
            raise ValueError(Options.INVALID_PORT_ERROR)

    def _raise_on_invalid_dir(self):
        for dir in self.dirs:
            if not os.path.isdir(dir):
                raise ValueError(Options.INVALID_DIR_ERROR % dir)

    def _raise_on_invalid_protocol(self):
        if self.protocol not in ('tcp', 'udp'):
            raise ValueError(Options.INVALID_PROTOCOL_ERROR % self.protocol)

    @staticmethod
    def _raise_on_invalid_debug(debug):
        if debug not in ("True", "False"):
            raise ValueError(Options.INVALID_DEBUG_ERROR % debug)

    @classmethod
    def _get_defaults(cls, is_snap):
        return Args(dirs="/tmp", perms_mask=None, syslog_server="127.0.0.1",
                syslog_port=514, log_file=cls._get_default_log_file(is_snap),
                tcp=False, debug=False)

    @classmethod
    def get_default_config_file(cls, is_snap):
        return cls._get_default_file_path('/etc/', 'owwatcher.conf', is_snap)

    @classmethod
    def _get_default_log_file(cls, is_snap):
        return cls._get_default_file_path('/var/log', 'owwatcher.log', is_snap)

    @staticmethod
    def _get_default_file_path(default_path, file_name, is_snap):
        if is_snap:
            return os.path.join(os.getenv('SNAP_DATA'), file_name)

        return os.path.join(default_path, file_name)
