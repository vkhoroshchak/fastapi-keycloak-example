import logging
import os
import uuid
from typing import Any, Generic, TypeVar

import structlog
from structlog.typing import EventDict

RendererType = TypeVar("RendererType")


Logger = structlog.stdlib.BoundLogger

VALID_LOG_FORMATS = {"json", "console"}
DEFAULT_LOG_FORMAT = "console"
DEFAULT_LOG_LEVEL = "DEBUG"

LOG_FORMAT = os.environ.get("LOG_FORMAT", DEFAULT_LOG_FORMAT).lower()
if LOG_FORMAT not in VALID_LOG_FORMATS:
    raise ValueError(f"Invalid LOG_FORMAT: {LOG_FORMAT}. Choose from {VALID_LOG_FORMATS}.")

LOG_LEVEL_STR = os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
try:
    LOG_LEVEL = getattr(logging, LOG_LEVEL_STR)
except AttributeError:
    print(f"Invalid LOG_LEVEL: {LOG_LEVEL_STR}. Defaulting to {DEFAULT_LOG_LEVEL}.")
    LOG_LEVEL = getattr(logging, DEFAULT_LOG_LEVEL)

IS_PRODUCTION = os.environ.get("ENVIRONMENT") == "production"
if IS_PRODUCTION:
    LOG_FORMAT = "json"


def drop_color_message_key(_, __, event_dict: EventDict) -> EventDict:
    """
    Uvicorn logs the message a second time in the extra `color_message`, but we don't
    need it. This processor drops the key from the event dict if it exists.
    """
    event_dict.pop("color_message", None)
    return event_dict


class Logging(Generic[RendererType]):
    """Customized implementation inspired by the following documentation:

    https://www.structlog.org/en/stable/standard-library.html#rendering-using-structlog-based-formatters-within-logging
    """

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        drop_color_message_key,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.FILENAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.FUNC_NAME,
            ]
        ),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
    ]

    @classmethod
    def get_processors(cls) -> list[Any]:
        if IS_PRODUCTION:
            cls.shared_processors.append(structlog.processors.format_exc_info)

        return cls.shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter]

    @classmethod
    def get_renderer(cls) -> RendererType:
        raise NotImplementedError()

    @classmethod
    def configure_stdlib(
        cls,
    ) -> None:
        level = LOG_LEVEL

        if IS_PRODUCTION:
            cls.shared_processors.append(structlog.processors.format_exc_info)

        logging.config.dictConfig(
            {
                "version": 1,
                "disable_existing_loggers": True,
                "formatters": {
                    "myLogger": {
                        "()": structlog.stdlib.ProcessorFormatter,
                        "processors": [
                            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                            cls.get_renderer(),
                        ],
                        "foreign_pre_chain": cls.shared_processors,
                    },
                },
                "handlers": {
                    "default": {
                        "level": level,
                        "class": "logging.StreamHandler",
                        "formatter": "myLogger",
                    },
                },
                "loggers": {
                    "": {
                        "handlers": ["default"],
                        "level": level,
                        "propagate": False,
                    },
                    # Propagate third-party loggers to the root one
                    **{
                        logger: {
                            "handlers": [],
                            "propagate": True,
                        }
                        for logger in [
                            "uvicorn",
                            "sqlalchemy",
                            "arq",
                        ]
                    },
                },
            }
        )

    @classmethod
    def configure_structlog(cls) -> None:
        structlog.configure_once(
            processors=cls.get_processors(),
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    @classmethod
    def configure(cls) -> None:
        cls.configure_stdlib()
        cls.configure_structlog()


class Development(Logging[structlog.dev.ConsoleRenderer]):
    @classmethod
    def get_renderer(cls) -> structlog.dev.ConsoleRenderer:
        return structlog.dev.ConsoleRenderer(colors=True)


class Production(Logging[structlog.processors.JSONRenderer]):
    @classmethod
    def get_renderer(cls) -> structlog.processors.JSONRenderer:
        return structlog.processors.JSONRenderer()


def configure_logging() -> None:
    if IS_PRODUCTION:
        Production.configure()
    else:
        Development.configure()


def generate_correlation_id() -> str:
    return str(uuid.uuid4())

def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger instance"""
    return structlog.get_logger(name)
