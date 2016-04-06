# encoding: utf-8
require 'digest'
require "logstash/filters/base"
require "logstash/namespace"
require "net/https"
require "uri"


# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::HTTPhash < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "httphash"

  config :input_url, :validate => :string, :default => "http://www.google.com"
  config :output_var, :validate => :string, :default => "signature"
  config :algorithm, :validate => :string, :default => "sha256"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    # do http request
    uri = URI.parse(@input_url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Get.new(uri.request_uri)
    request.initialize_http_header({"User-Agent" => "httphash"})

    response = http.request(request)

    event[@output_var] = do_hash(response.body, @algorithm)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  def do_hash(body, method)
    if method == "sha256"
      return Digest::SHA256.hexdigest(body)
    end
    return nil
  end
end # class LogStash::Filters::Example
