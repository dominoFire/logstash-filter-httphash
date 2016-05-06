# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "helpers/url_resolver"
require "helpers/hasher"

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

  config :input_url_var, :validate => :string, :default => "http://www.google.com"
  config :output_var, :validate => :string, :default => "signature"
  config :size_bytes_var, :validate => :string, :default => "size_bytes"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    begin
      req_body = UrlResolver.resolve(event[@input_url_var])
      hash_str = Hasher.do_hash(req_body, "sha256").force_encoding(Encoding::UTF_8)
      size_bytes = req_body.length
    rescue Exception => e
      #puts "Error" + e.message
      #puts e.backtrace.join("\n")
      @logger.debug("FUU: " + e.message + "\n" + e.backtrace.join("\n"))
      hash_str = nil
      size_bytes = 0
    end
    event[@size_bytes_var] = size_bytes
    event[@output_var] = hash_str
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example
