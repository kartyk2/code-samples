import logging
import logging.handlers
import asyncio
import traceback
from queue import SimpleQueue

# Create a queue and a queue handler
app_queue = SimpleQueue()
app_queue_handler = logging.handlers.QueueHandler(app_queue)

# Create a listener with handlers
app_stream_handler = logging.StreamHandler()
app_file_handler = logging.FileHandler('app.log')
app_listener = logging.handlers.QueueListener(app_queue, app_stream_handler, app_file_handler)

# Configure the logger
logger = logging.getLogger('main')
logger.setLevel(logging.INFO)
logger.addHandler(app_queue_handler)

async def log_app():
    logger.info('App started')
    logger.info('App finished')
    print("hello")

app_listener.start()
try:
    asyncio.run(log_app())
except:
    print(traceback.format_exc())
finally:
    app_listener.stop()

app_stream_handler.close()
app_file_handler.close()
