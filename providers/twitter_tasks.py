from time import sleep
from feedlight.settings import TWITTER_APP_TOKEN, TWITTER_APP_SECRET
from feedlight.models import User, Document
from bson.objectid import ObjectId
from feedlight.providers import celery, create_or_update_document
from dateutil.parser import parse
from datetime import datetime

@celery.task
def twitter_feed(user_id):
    try:
        from feedlight.app import twitter
        u = User.find_one({'_id': ObjectId(user_id)})
        user_id = u._id

        if not u:
            return

        credentials = u.credentials['twitter']
        twitter.tokengetter_func = lambda: (credentials['token'],
            credentials['secret'])
        twitter_meta = u.meta['twitter']
        # First time we run this, process "only" 800 tweets
        if not twitter_meta.get('last_id', None):
            statuses = twitter.get('statuses/home_timeline.json', data={'count':200,
                'include_entities': True}).data

            for s in statuses:
                process_tweet(s, user_id)

            u.meta['twitter']['last_id'] = statuses[0]['id']
            u.save()

        # Read only last tweets
        else:
            last_id = twitter_meta['last_id']
            max_id = None
            statuses = twitter.get('statuses/home_timeline.json', data={
                'since_id': last_id, 'count': 800, 'include_entities': True}).data

            if statuses:
                since_id = statuses[0]['id']
                while statuses:
                    if statuses[-1]['id'] == max_id:
                        break
                    max_id = statuses[-1]['id']
                    for s in statuses:
                        process_tweet(s, user_id)
                    statuses = twitter.get('statuses/home_timeline.json', data={
                        'max_id': max_id - 1, 'since_id': last_id, 'count': 800,
                        'include_entities': True}).data
                u.meta['twitter']['last_id'] = since_id
                u.save()
    finally:
        keep_running = True
        if keep_running:
            twitter_feed.apply_async(args=[user_id], countdown=60)

def process_tweet(tweet, user_id):
    if not len(tweet['entities']['urls']):
        return

    for url in tweet['entities']['urls']:

        if not isinstance(tweet['created_at'], datetime):
            created_time = parse(tweet['created_at'])
        else:
            created_time = tweet['created_at']


        source = {'created_at': created_time, 'id': tweet['id'], 'user_name':
            tweet['user']['name']}

        create_or_update_document(url['expanded_url'], user_id, 'twitter',
            generate_tweet_source_id(tweet), source, created_time)


def generate_tweet_source_id(tweet):
    return 'tweet-%s' % tweet['id']
