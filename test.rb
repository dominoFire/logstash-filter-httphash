require 'digest'
require "net/http"
require "uri"

def do_request(my_url, use_ssl)
  uri = URI.parse(my_url)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = use_ssl
  request = Net::HTTP::Get.new(uri.request_uri)

  response = http.request(request)

  return response.body.force_encoding(Encoding::UTF_8)
end

def do_hash(body, method)
  if method == "sha256"
    return Digest::SHA256.hexdigest(body).force_encoding(Encoding::UTF_8)
  end
  return nil
end

do_hash(do_request("http://barbon.mx", false), "sha256")
