import logging
import logging.handlers
from queue import SimpleQueue

from async_logging.queue_listner import SingleThreadQueueListener


class LogContext:

    def __init__(self):
        self.listeners = []

    def iter_loggers(self):
        """Iterates through all registered loggers."""
        for name in logging.root.manager.loggerDict:
            yield logging.getLogger(name)
        yield logging.getLogger()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def open(self):
        """Replace all loggers' handlers with a new listener."""
        for logger in self.iter_loggers():
            if handlers := logger.handlers:
                queue = SimpleQueue()
                listener = SingleThreadQueueListener(queue, *handlers)
                logger.handlers = [logging.handlers.QueueHandler(queue)]
                self.listeners.append((listener, logger))
                listener.start()

    def close(self):
        """Stops the listener and restores all original handlers."""
        while self.listeners:
            listener, logger = self.listeners.pop()
            logger.handlers = listener.handlers
            listener.stop()