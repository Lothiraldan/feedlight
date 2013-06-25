import requests

from settings import *
from dateutil.parser import parse
from picomongo import Document as BaseDocument

from urllib import urlencode
from urlparse import urlparse, urlunparse, urlsplit, urlunsplit


class cached(object):
    def __init__(self, f):
        self.cached = {}
        self.f = f

    def __call__(self, other_self, *args, **kwargs):
        if self.cached.get(other_self._id):
            return self.cached[other_self._id]
        self.cached[other_self._id] = self.f(other_self, *args, **kwargs)
        return self.cached[other_self._id]



class Document(BaseDocument):

    @property
    @cached
    def summary(self):
        return DocumentSummary.find_one({'_id': self.summary_id})


class User(BaseDocument):

    def __init__(self, *args, **kwargs):
        super(BaseDocument, self).__init__(*args, **kwargs)
        self.col.ensure_index('user')


class DocumentSummary(BaseDocument):

    @classmethod
    def get_or_create_by_url(cls, url):
        real_url = unshorten_url(url)
        # Remove http or https
        standardized_url = urlunsplit(('',)+urlsplit(real_url)[1:])

        doc = cls.find_one({'standardized_url': standardized_url})

        if doc:
            print "Existing doc for url %s" % standardized_url
            return doc._id

        doc = cls()

        print "Not existing doc for url %s" % standardized_url
        diffbot_request = requests.get('http://www.diffbot.com/api/article',
            params={'token': DIFFBOT_APP_TOKEN, 'url': real_url,
            'html': True})
        diffbot_response = diffbot_request.json()
        if diffbot_response.get('errorCode', 0):
            return None
        doc.update(diffbot_response)
        doc.standardized_url = standardized_url
        date = doc.get('date', None)
        try:
            if date:
                doc['date'] = parse(date)
        except ValueError:
            doc['date'] = None
        doc.save()
        return doc._id


# Utils


headers = {
    'User-Agent': 'FeedLight'
}

def unshorten_url(url):
    x = {'r': url, 't': 'json'}
    r = requests.get('http://api.unshort.me/?%s' % urlencode(x), headers=headers)

    if 'xml' in r.text:
        return url

    response = r.json()

    if response['success'] == 'false':
        return url
    else:
        parsed_url = list(urlparse(response['resolvedURL']))
        parsed_url[4] = '&'.join(
            [x for x in parsed_url[4].split('&') if not 'utm_' in x])
        utmless_url = urlunparse(parsed_url)
        return utmless_url.lower()

