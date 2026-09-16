class ChainPwnError(Exception):
    pass


class ToolNotFoundError(ChainPwnError):
    pass


class ToolExecutionError(ChainPwnError):
    pass


class ValidationError(ChainPwnError):
    pass


class ExploitError(ChainPwnError):
    pass


class ShellError(ChainPwnError):
    pass


class ConfigError(ChainPwnError):
    pass
