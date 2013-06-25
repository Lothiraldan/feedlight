from feedlight.settings import FACEBOOK_APP_TOKEN, FACEBOOK_APP_SECRET

from feedlight.models import User, Document
from bson.objectid import ObjectId
from feedlight.providers import celery, create_or_update_document
from dateutil.parser import parse

@celery.task
def facebook_feed(user_id):
    try:
        from feedlight.app import facebook
        u = User.find_one({'_id': ObjectId(user_id)})
        user_id = u._id

        if not u:
            return

        credentials = u.credentials['facebook']
        facebook.tokengetter_func = lambda: (credentials['token'],
            '')
        facebook_meta = u.meta['facebook']

        # First time we run this
        if not facebook_meta.get('last_id', None):
            data = facebook.get('/me/home', data={'count': 200,
                'include_entities': True}).data

            posts = data['data']
            last_id = posts[0]['id']

            if posts:
                since_id = posts[0]['id']

                max_id = None
                loops = 0
                while posts and loops < 5:
                    loops += 1
                    if posts[-1]['id'] == max_id:
                        break
                    max_id = posts[-1]['id']
                    for post in posts:
                        process_post(post, user_id)
                    next_url = data['paging']['next']
                    next_url = next_url.replace('https://graph.facebook.com/', '')
                    posts = facebook.get(next_url, data={'count': 200,
                        'include_entities': True}).data['data']
            u.meta['facebook']['last_id'] = since_id
            u.save()
        else:
            last_id = facebook_meta['last_id']

            data = facebook.get('/me/home', data={'count': 200,
                'since_id': last_id}).data
            posts = data['data']

            if posts:
                since_id = posts[0]['id']
                while posts:
                    for post in posts:
                        if post['id'] == last_id:
                            print "I've already seen this post %s" % post['id']
                            break
                        process_post(post, user_id)
                    else:
                        next_url = data['paging']['next']
                        next_url = next_url.replace('https://graph.facebook.com/', '')
                        posts = facebook.get(next_url, data={'count': 200,
                            'include_entities': True}).data['data']
                        continue
                    print "End of loop, break"
                    break
                u.meta['facebook']['last_id'] = since_id
                u.save()
    finally:
        keep_running = True
        if keep_running:
            facebook_feed.apply_async(args=[user_id], countdown=60)


def process_post(post, user_id):
    if not post.get('link', None):
        return

    url = post['link']
    if 'www.facebook.com' in url:
        return

    created_time = parse(post['created_time'])

    source = {'created_at': created_time, 'link': post['actions'][0]['link'],
        'user_name': post['from']['name']}

    create_or_update_document(url, user_id, 'facebook',
        generate_post_source_id(post), source, created_time)


def generate_post_source_id(post):
    return 'facebook-post-%s' % post['id']
