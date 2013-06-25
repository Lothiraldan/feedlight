$(document).ready(function() {

    Read = function(article) {
        if(!article.hasClass('read')) {
            var count = $('span.links-count');
            count.text(parseInt(count.text()) - 1);
            article.addClass('read');
            $.ajax('/read/' +  article.attr('id'));
        }
    }

    Unread = function(article) {
        if(article.hasClass('read')) {
            var count = $('span.links-count');
            count.text(parseInt(count.text()) + 1);
            article.removeClass('read');
            $.ajax('/read/' + article.attr('id') + '?read=False');
        }
    }

    $('.unread').on('click', function(event) {
        var article = $(this).parent().parent().parent().parent();
        Unread(article);
        event.preventDefault();
    });

    $('.push-to-pocket').on('click', function(event) {
        var article = $(this).parent().parent().parent().parent();
        Read(article);
        $.ajax('/push_to_pocket/' +  article.attr('id'));
        event.preventDefault();
    });

    $('#content-inner').chaves();

    $('.is-post').waypoint(function(direction) {
        if(direction == 'down') {
            Read($(this));
        }
    });
});
