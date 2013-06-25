CELERY_IMPORTS = ("feedlight.providers.twitter_tasks", )
CELERY_RESULT_BACKEND = "mongodb"
CELERY_MONGODB_BACKEND_SETTINGS = {
    "host": "localhost",
    "port": 27017,
    "database": "tasks",
}
BROKER_URL = "mongodb://localhost:27017/tasks"
CELERY_IGNORE_RESULT = True
CELERY_TIMEZONE = 'Europe/London'
CELERY_ACKS_LATE = True
CELERYD_PID_FILE = '.'
