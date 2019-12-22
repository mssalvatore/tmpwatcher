import os

class Options:
    INVALID_DIR_ERROR = "The directory '%s' does not exist."
    INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
    INVALID_PROTOCOL_ERROR = "Unknown protocol '%s'. Valid protocols are 'udp' or 'tcp'."
    INVALID_DEBUG_ERROR = "'%s' is not a valid value for the debug option. Valid values are 'True' or 'False'."

    def __init__(self, args, config, is_snap=False):
        self.dirs = Options._merge_dirs_option(args, config, "/tmp")
        self.syslog_port = Options._merge_syslog_port_option(args, config, 514)
        self.syslog_server = Options._merge_syslog_server_option(args, config, "127.0.0.1")
        self.log_file = Options._merge_log_file_option(args, config, Options._get_default_log_file(is_snap))
        self.protocol = Options._merge_protocol_option(args, config, "udp")
        self.debug = Options._merge_debug_option(args, config, False)

        self._raise_on_invalid_options()

    @staticmethod
    def _merge_dirs_option(args, config, default):
        return Options._merge_single_option('dirs', args.dirs, config, default).split(',')

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

        return default

    @staticmethod
    def _merge_debug_option(args, config, default):
        if args.debug:
            return True

        if 'debug' in config['DEFAULT']:
            Options._raise_on_invalid_debug(config['DEFAULT']['debug'])
            return True if config['DEFAULT']['debug'] == 'True' else False

        return default

    def _raise_on_invalid_options(self):
        self._raise_on_invalid_syslog_port()
        self._raise_on_invalid_protocol()
        self._raise_on_invalid_dir()

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

    @staticmethod
    def get_default_config_file(is_snap):
        return Options._get_default_file_path('/etc/', 'owwatcher.conf', is_snap)

    @staticmethod
    def _get_default_log_file(is_snap):
        return Options._get_default_file_path('/var/log', 'owwatcher.log', is_snap)

    @staticmethod
    def _get_default_file_path(default_path, file_name, is_snap):
        if is_snap:
            return os.path.join(os.getenv('SNAP_DATA'), file_name)

        return os.path.join(default_path, file_name)
