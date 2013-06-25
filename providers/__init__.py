from celery import Celery
from feedlight.models import User, Document, DocumentSummary
import requests
import pytz

utc=pytz.UTC
celery = Celery()
celery.conf.update({
    'CELERY_IMPORTS': ("feedlight.providers.twitter_tasks", ),
    'CELERY_RESULT_BACKEND': "mongodb",
    'CELERY_MONGODB_BACKEND_SETTINGS': {
        "host": "localhost",
        "port": 27017,
        "database": "tasks",
    },
    'BROKER_URL': "mongodb://localhost:27017/tasks",
    'CELERY_IGNORE_RESULT': True,
    'CELERY_TIMEZONE': 'Europe/London',
    'CELERY_ACKS_LATE': True
})

def create_or_update_document(url, user_id, source_type, source_id, source,
        last_source_date):
    summary_id = DocumentSummary.get_or_create_by_url(url)

    # Unable to download summary???
    if not summary_id:
        return

    doc = Document.find_one({'summary_id': summary_id, 'user': user_id})
    print "Document for summary %s for user %s : %s" % (summary_id, user_id, doc is not None)

    if doc is None:
        doc = Document({'summary_id': summary_id, 'user': user_id, 'read': False})
        doc.sources = {source_id: {'from': source_type, 'source': source}}
        doc.sources_count = {source_type: 1}
        doc.last_source_date = last_source_date
        doc.last_source = source_type
        print "Create doc with summary_id", doc.summary_id
        doc.save()
    else:
        print "Update document !!!"
        if last_source_date > utc.localize(doc.last_source_date):
            doc.last_source_date = last_source_date
            doc.last_source = source_type
        if not source_id in doc.sources:
            doc.sources_count[source_type] = doc.sources_count.get(source_type, 0) + 1
        doc.sources[source_id] = {'from': source_type, 'source': source}
        doc.save()

from twitter_tasks import twitter_feed
from facebook_tasks import facebook_feed
