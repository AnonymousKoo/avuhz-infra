"""Console entry point for the local-only Avuhz service."""
from .composition import LocalServiceSettings, create_local_application
from .server import serve


def main():
    try:
        settings = LocalServiceSettings.from_environment()
        application = create_local_application(settings)
    except (RuntimeError, ValueError):
        raise SystemExit("Avuhz local service configuration is invalid") from None
    try:
        serve(application, settings.host, settings.port)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
