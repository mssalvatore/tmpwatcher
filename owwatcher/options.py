import collections
from distutils import util
import os

Args = collections.namedtuple('Args', 'dirs perms_mask syslog_port syslog_server tcp stdout log_file debug')

class Options:
    INVALID_DIR_ERROR = "The directory '%s' does not exist."
    PERMS_FORMAT_MSG = "The permissions mask must be an octal integer (e.g. 755) between 0 and 777 inclusive."
    INVALID_PERMS_ERROR = "%s is an invalid permissions mask. " + PERMS_FORMAT_MSG
    INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
    INVALID_PROTOCOL_ERROR = "Unknown protocol '%s'. Valid protocols are 'udp' or 'tcp'."
    INVALID_STDOUT_ERROR = "'%s' is not a valid value for the stdout option. Valid values are 'True' or 'False'."
    INVALID_DEBUG_ERROR = "'%s' is not a valid value for the debug option. Valid values are 'True' or 'False'."


    def __init__(self, args, is_snap=False):
        defaults = Options._get_defaults(is_snap)

        self.dirs = (args.dirs if args.dirs is not None else defaults.dirs).split(',')
        self.perms_mask = Options._perms_mask_args_or_default(args, defaults.perms_mask)
        self.syslog_port = int(args.syslog_port) if args.syslog_port is not None else defaults.syslog_port
        self.syslog_server = args.syslog_server if args.syslog_server is not None else defaults.syslog_server
        self.log_file = args.log_file if args.log_file is not None else defaults.log_file
        self._protocol = Options._protocol_args_or_default(args, defaults.tcp)
        self.stdout = args.stdout if args.stdout else defaults.stdout
        self.debug = args.debug if args.debug else defaults.debug

        self._raise_on_invalid_options()

    @staticmethod
    def _perms_mask_args_or_default(args, default):
        mask = args.perms_mask if args.perms_mask is not None else default

        if isinstance(mask, int) or mask is None:
            return mask

        try:
            return int(mask, 8)
        except ValueError:
            raise TypeError(Options.PERMS_FORMAT_MSG)

    @staticmethod
    def _protocol_args_or_default(args, default):
        if args.tcp:
            return args.tcp

        if default:
            return default

        return False

    def _raise_on_invalid_options(self):
        self._raise_on_invalid_perms_mask()
        self._raise_on_invalid_syslog_port()
        self._raise_on_invalid_protocol()
        self._raise_on_invalid_dir()
        self._raise_on_invalid_stdout()
        self._raise_on_invalid_debug()

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
        for d in self.dirs:
            if not os.path.isdir(d):
                raise ValueError(Options.INVALID_DIR_ERROR % d)

    def _raise_on_invalid_protocol(self):
        Options._raise_on_invalid_bool(self._protocol, Options.INVALID_PROTOCOL_ERROR)

    def _raise_on_invalid_stdout(self):
        Options._raise_on_invalid_bool(self.stdout, Options.INVALID_STDOUT_ERROR)

    def _raise_on_invalid_debug(self):
        Options._raise_on_invalid_bool(self.debug, Options.INVALID_DEBUG_ERROR)

    @staticmethod
    def _raise_on_invalid_bool(value, error_msg):
        if not isinstance(value, bool):
            raise ValueError(error_msg % value)

    @property
    def protocol(self):
        if self._protocol:
            return "tcp"

        return "udp"

    @classmethod
    def _get_defaults(cls, is_snap):
        return Args(dirs="/tmp", perms_mask=None, syslog_server="127.0.0.1",
                syslog_port=514, tcp=False, stdout=False,
                log_file=cls._get_default_log_file(is_snap), debug=False)

    @classmethod
    def _get_default_log_file(cls, is_snap):
        return cls._get_default_file_path('/var/log', 'owwatcher.log', is_snap)

    @staticmethod
    def _get_default_file_path(default_path, file_name, is_snap):
        if is_snap:
            return os.path.join(os.getenv('SNAP_DATA'), file_name)

        return os.path.join(default_path, file_name)

    @classmethod
    def config_to_tuple(cls, config, is_snap):
        try:
            config_with_defaults = cls._populate_config_with_defaults(config, is_snap)

            return Args(**config_with_defaults)
        except TypeError as te:
            raise TypeError("Error reading config file. The config "\
                    "file may contain an unrecognized option: %s" % str(te))

    #TODO: I hate the complexity of this. Do something better.
    @classmethod
    def _populate_config_with_defaults(cls, config, is_snap):
        new_config = {}
        defaults = cls._get_defaults(is_snap)

        for option in defaults._fields:
            if option not in config["DEFAULT"]:
                new_config[option] = defaults._asdict()[option]
            else:
                new_config[option] = config["DEFAULT"][option]

            if new_config[option] in ['True', 'False']:
                new_config[option] = bool(util.strtobool(new_config[option]))

        cls._transform_config_protocol(config, new_config)

        return new_config

    @staticmethod
    def _transform_config_protocol(config, new_config):
        # NOTE: config["tcp"] has already been populated with the default
        if "protocol" in config["DEFAULT"]:
            if config["DEFAULT"]["protocol"] == "tcp":
                new_config["tcp"] = True
            elif config["DEFAULT"]["protocol"] == "udp":
                new_config["tcp"] = False
            else:
                new_config["tcp"] = config["DEFAULT"]["protocol"]
