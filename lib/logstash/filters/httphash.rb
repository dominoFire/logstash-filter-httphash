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

  config :input_url, :validate => :string, :default => "http://www.google.com"
  config :output_var, :validate => :string, :default => "signature"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    event[@output_var] = Hasher.do_hash(UrlResolver.resolve(@input_url), "sha256").force_encoding(Encoding::UTF_8)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example
