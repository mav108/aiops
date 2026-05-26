import asyncio
import logging

from aiops_agent.config import get_settings

logger = logging.getLogger("aiops_agent.worker")


async def run_forever() -> None:
    settings = get_settings()
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting AIOps worker in %s mode", settings.execution_mode)
    while True:
        logger.info("Worker heartbeat; Service Bus consumption is an extension point for v1.")
        await asyncio.sleep(60)


def main() -> None:
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()

