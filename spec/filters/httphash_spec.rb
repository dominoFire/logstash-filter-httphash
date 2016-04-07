# encoding: utf-8
require 'spec_helper'
require "logstash/filters/httphash"

describe LogStash::Filters::HTTPhash do
  describe "A bunch of URL's" do
    let(:config) do <<-CONFIG
      filter {
        httphash {
          input_url => "msg"
          output_var => "a_sign"
        }
      }
    CONFIG
    end

    sample("msg" => "http://barbon.mx") do
      expect(subject).to include("a_sign")
      expect(subject['a_sign']).to eq("371d709177f44e2b8788a29558d2f29d9b09ac301c345b966d2e5e0b8f626317")
    end
  end

  describe "Another url" do
    let(:config) do <<-CONFIG
      filter {
        httphash {
          input_url => "msg"
          output_var => "other_sign"
        }
      }
    CONFIG
    end

    sample("msg" => "https://propiedadescom.s3.amazonaws.com/files/600x400/novena-1234-mexicali-playas-de-rosarito-baja-california-norte-1649546-foto-01.jpg") do
      expect(subject).to include("other_sign")
      expect(subject['other_sign']).to eq("a4b2d2aee129b372482b8eab454fafd8f5f7285f648d2c35a56617c15d079650")
    end

    # HTTP 403
    sample("msg" => "https://propiedadescom.s3.amazonaws.com/files/original/656518c39b1685c50bb4a4671ffb812f.JPG") do
      expect(subject).to include("other_sign")
      expect(subject['other_sign']).to eq(nil)
    end
  end
end
