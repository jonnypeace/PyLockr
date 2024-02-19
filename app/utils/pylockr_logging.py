import logging

class PyLockrLogs:
    '''
    PyLockrLogs
    -----------

    Useage:
        Create an instance of the PyLockrLogs class:
        logger = PyLockrLogs('myapp', 'myapp.log', logging.INFO)

        Log some messages:
        logger.info('This is an info message.')
        logger.warning('This is a warning message.')
        logger.error('This is an error message.')
    '''

    def __init__(self, name=__name__, log_file='flask.log', level=logging.INFO):
        # Create a logger
        self.logger = logging.getLogger(name)

        # Check if the logger already has handlers to prevent adding them again
        if not self.logger.handlers:
            self.logger.setLevel(level)
            
            # Create a file handler for writing logs to a file
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            
            # Create a stream handler for writing logs to the console
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(level)
            
            # Create a formatter and set it for both handlers
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            stream_handler.setFormatter(formatter)
            
            # Add handlers to the logger
            self.logger.addHandler(file_handler)
            self.logger.addHandler(stream_handler)
        
    def info(self, message):
        '''
        Usage:
            logger = PyLockrLogs('myapp', 'myapp.log', logging.INFO)
            logger.info('xyz')
        '''
        self.logger.info(message)

    def error(self, message):
        '''
        Usage:
            logger = PyLockrLogs('myapp', 'myapp.log', logging.INFO)
            logger.error('xyz')
        '''
        self.logger.error(message)

    def warning(self, message):
        '''
        Usage:
            logger = PyLockrLogs('myapp', 'myapp.log', logging.INFO)
            logger.warning('xyz')
        '''
        self.logger.warning(message)
