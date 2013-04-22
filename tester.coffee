module.exports = ->

  doctype 5

  html ->

    head ->

      title 'API Tester'

      script src: 'https://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js', type: 'text/javascript'
      script src: 'http://www.webtoolkit.info/djs/webtoolkit.sha1.js', type: 'text/javascript'

      script """
        window.headername = "#{@headername}";
        window.granularity = "#{@granularity}";
      """

      coffeescript -> $ ->

          $('#submit').click ->

            time = Math.floor Date.now() / granularity
            headers = {}
            headers[headername] = "#{ $('[name=userid]').val() }:#{ SHA1 "#{$('[name=password]').val()}#{time}" }"
            method = $('[name=method]').val()
            request = $('[name=request]').val()

            $.ajax
              url: $('[name=endpoint]').val()
              type: method
              headers: headers
              contentType: if method == 'GET' then 'application/x-www-form-urlencoded; charset=UTF-8' else 'application/json'
              data: if method == 'GET' then JSON.parse request else request
              complete: (xhr, status) ->
                xhr.responseText = JSON.parse xhr.responseText || "{}"
                $('[name=response]').val JSON.stringify xhr, null, "  "

      style """
        body > * {
          display: block;
        }
        body > textarea {
          width: 100%;
          height: 300px;
        }
        [name=endpoint] {
          width: 100%;
        }
      """

    body ->

      input name: 'userid', type: 'text', placeholder: 'User ID'
      input name: 'password', type: 'text', placeholder: 'Password hash'
      input name: 'endpoint', type: 'text', placeholder: 'Path to endpoint'
      select name: 'method', ->
        option 'GET'
        option 'POST'
        option 'PUT'
        option 'DELETE'
      p 'Request'
      textarea name: 'request'
      p 'Response'
      textarea name: 'response'
      input type: 'button', value: 'Submit', id: 'submit'
